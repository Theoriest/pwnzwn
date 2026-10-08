# Masterclass: IP-Header Spoofing & Trusting Client Input, the VINYL VAULT Privesc, From Zero

**Companion to:** `vinylvault-header-spoof-writeup.md`

This box is a privilege-escalation lesson wrapped in two decoys. The real bug, trusting a client-controlled "source IP" header, is one of the most common access-control mistakes in real apps. This guide explains, from zero: how HTTP headers and proxies work, why `X-Forwarded-For`/`X-Real-IP` exist and why you can't trust them, what "mass assignment" / client-trust privesc is, how to drive it in **Burp Suite**, and how to fix all of it.

---

## How to read this

- **Part 0**, HTTP requests, headers, and how a server learns your IP.
- **Part 1**, the one idea behind every "trusting the client" bug.
- **Part 2**, decoy #1: client-controlled `access_level` (and why statelessness killed it).
- **Part 3**, decoy #2 & the real bug: proxy IP headers (`X-Forwarded-For` vs `X-Real-IP`).
- **Part 4**, doing it in Burp Suite (capture → modify → forward).
- **Part 5**, the fixes.
- **Glossary**.

---

# PART 0, HTTP Requests, Headers, and "What's My IP?"

An HTTP request is a method + path + a set of **headers** (metadata) + an optional body:
```
GET /admin HTTP/1.1
Host: 54.72.82.22:8180
User-Agent: curl/8.0
X-Real-IP: 127.0.0.1          ← a header; just text the client typed
```
**The key fact for this whole box:** *every header is supplied by the client.* The server only knows what you send it. A header named `X-Real-IP` is not magically "your real IP", it's a string you put there. Naming doesn't equal trust.

### How a server *actually* learns your IP
- The **only** trustworthy source is the **TCP socket**, the peer address of the connection (`request.remote_addr` in Flask). That's set by the network stack, not by you.
- **Proxy headers** (`X-Forwarded-For`, `X-Real-IP`) exist because when a request passes through a load balancer / reverse proxy, the app behind it would otherwise see the *proxy's* IP, not yours. So the proxy *adds* a header saying "the original client was 1.2.3.4."
- The catch: if the app reads that header **without a trusted proxy actually setting it**, anyone can just send it themselves. That's the vulnerability.

---

# PART 1, The One Idea

Every "trusting the client" bug is the same sentence:

> **The server believed something the client said, as if the server had determined it.**

- Decoy #1: the server believed `access_level=admin` because the client *said so*.
- The real bug: the server believed the request came from `127.0.0.1` because the client *said so* (via `X-Real-IP`).

Anything that arrives in the request, body fields, cookies, **and headers**, is attacker-controlled. Trust must come from something the server computes or verifies, never from a client's claim.

---

# PART 2, Decoy #1: Client-Controlled `access_level`

The login form:
```html
<select name="access_level"><option value="user">User</option></select>
```
Only `user` is offered. But the dropdown is **client-side UI**, the server just receives `access_level=<whatever>` in the POST body. Sending `access_level=admin` is trivial (edit it in Burp, or `curl --data access_level=admin`). This pattern, the client setting a field that controls privilege, is **mass-assignment / privilege-parameter tampering**.

**Why it was a decoy here:** the app is **stateless**, it never sets a session cookie, so "I claimed admin" isn't *remembered* between requests. The greeting changed to "Access level: admin," but `/admin` is a separate request that re-checks its own condition. With nothing persisted, the `access_level` claim evaporates. 

**The lesson:** always check whether a "successful" tamper actually *persists* and *grants* anything. Look for a `Set-Cookie`; if the app is stateless, a reflected value is often cosmetic. (On a box that *did* store it, `access_level=admin` would be the whole exploit, so it's always worth one test.)

---

# PART 3, Decoy #2 and the Real Bug: Proxy IP Headers

### 3.1 The header family
Admin features are often restricted to "internal" or "localhost" callers. Apps check the client IP, and buggy ones check it via a **spoofable header**. The usual suspects:

| Header | Set by | Trustworthy from the client? |
|---|---|---|
| `X-Forwarded-For` | proxies (list of hops) | **No** |
| `X-Real-IP` | nginx-style proxies (single IP) | **No** |
| `True-Client-IP` | some CDNs (Akamai/Cloudflare) | **No** |
| (socket peer) `remote_addr` | TCP stack | **Yes** |

### 3.2 The misdirection
The page's JavaScript **hardcodes `X-Forwarded-For: 8.8.8.8`**. That's deliberate bait: it screams "I check `X-Forwarded-For`." But spoofing XFF to `127.0.0.1` did nothing, the server actually reads **`X-Real-IP`**. The challenge author dangled one header while trusting another.

**How to beat misdirection like this:** when you suspect IP gating, don't test only the header you're shown, test the **whole family**. One request each:
```bash
for h in "X-Forwarded-For: 127.0.0.1" "X-Real-IP: 127.0.0.1" "True-Client-IP: 127.0.0.1"; do
  curl -s http://TARGET/admin -H "$h" | grep -o 'safctf{[^}]*}'
done
```
`X-Real-IP: 127.0.0.1` is the one that flips `403 Access denied` → the admin page + flag.

### 3.3 Why `127.0.0.1`?
`127.0.0.1` (localhost) is the address a process uses to talk to *itself*. Apps frequently treat "request from localhost" as "came from a trusted internal admin/console." By claiming `X-Real-IP: 127.0.0.1`, you impersonate the server's own loopback and inherit that trust. (Try `::1` too, the IPv6 loopback, when `127.0.0.1` doesn't take.)

---

# PART 4, Doing It in Burp Suite

Burp is the standard tool for exactly this "capture a request, change it, resend" workflow. The flow I used:

1. **Proxy + browser:** point your browser at Burp's proxy (or use Burp's embedded browser) so requests pass through Burp.
2. **Intercept:** in **Proxy → Intercept**, turn intercept on, click the `/admin` link; Burp pauses the request mid-flight.
3. **Modify:** add a header line to the raw request:
   ```
   X-Real-IP: 127.0.0.1
   ```
4. **Forward:** send it on; the response (the listening room + flag) comes back.

Even slicker: right-click the request → **Send to Repeater**, add the header there, and hit **Send**, Repeater lets you tweak and resend endlessly without re-triggering the browser. (That's the view in `vinyl-vault-burp.png`.)

**Why Burp over curl here?** They're equivalent for the final request, but Burp shines when you're *exploring*, you capture the app's real request (with all its headers/cookies) exactly as the browser sent it, then mutate one thing at a time. It also makes header/body tampering visual, which is why it's the natural tool for privilege-parameter and header-spoof bugs. (I confirmed the finding with a one-line `curl` afterward for the writeup.)

---

# PART 5, The Fixes

**Don't trust client IP headers.**
- Read the client IP from the **socket** (`request.remote_addr`), not from `X-Forwarded-For`/`X-Real-IP`.
- If you're legitimately behind a proxy, configure a trusted proxy list (e.g. Werkzeug's `ProxyFix` with a known hop count) and **strip inbound copies** of these headers at the edge so clients can't inject them.
- Never let a *claimed* `127.0.0.1` grant admin. Loopback-only features should bind to loopback at the network layer, not infer it from a header.

**Don't trust client privilege fields.**
- Authorization (`role`/`access_level`) must be decided server-side from an authenticated identity, never read from a form field or token the client can edit.

**General:** anything in the request, body, cookies, **headers**, is attacker input. Authenticate, then authorize from server-held state.

---

# Glossary

- **Header**, a line of request/response metadata; on a request, entirely client-supplied.
- **`remote_addr` / socket peer**, the IP of the actual TCP connection; the trustworthy source of "who connected."
- **`X-Forwarded-For` (XFF)**, proxy header listing original client + hops; spoofable if not set by a trusted proxy.
- **`X-Real-IP`**, nginx-style single-IP proxy header; same trust caveat. *(The real gate on this box.)*
- **Loopback / `127.0.0.1` / `::1`**, the address a host uses to reach itself; often (mis)trusted as "internal admin."
- **Mass assignment / parameter tampering**, the client setting a field (like `access_level`) that controls privilege.
- **Stateless app**, keeps no server session; a reflected "admin" claim isn't remembered (why decoy #1 failed).
- **Burp Suite**, intercepting proxy; capture → modify (Proxy/Repeater) → forward.
- **CWE-290 / CWE-348**, auth bypass by spoofing / use of less-trusted source (the header-trust bug).

---

# Where to Go Next

- In Burp, practise **Repeater**: capture any request, add `X-Forwarded-For`/`X-Real-IP`, and watch how different apps react. Learn to read `Set-Cookie` to tell stateful from stateless.
- Build a tiny Flask app that does `if request.headers.get("X-Real-IP")=="127.0.0.1": admin()`, exploit it, then fix it with `ProxyFix` + reading `remote_addr`.
- Learn the whole proxy-header family (`X-Forwarded-For`, `X-Real-IP`, `True-Client-IP`, `Forwarded`) and the SSRF/rate-limit/auth bypasses they enable.
- Keep the meta-habit from this box: **the clue they hand you is often the decoy, test the whole family, and check whether a tamper actually persists.**

The transferable idea: **a value is only as trustworthy as its source.** A header named `X-Real-IP` is not your real IP, it's a wish the client typed. Servers must verify, not believe.
