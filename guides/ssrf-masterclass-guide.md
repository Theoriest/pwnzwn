# Masterclass: Server-Side Request Forgery (SSRF), Turning a Fetcher Into a Pivot, From Zero

The bug behind ORBIT DISPATCH, explained from nothing. You'll learn what SSRF is and why it's so powerful in cloud environments, every family of filter bypass (and *why* each works), how to go from "it fetches a URL" to "I read an internal service / cloud credentials," how to find it in code and black-box, and how to actually stop it.

## How to read this

- **PART 0**, the mental model: whose network are you borrowing?
- **PART 1**, the one idea.
- **PART 2**, detection and confirming it's real.
- **PART 3**, what to point it at (the target map).
- **PART 4**, filter bypasses, by family, with the reasoning.
- **PART 5**, blind SSRF and escalation.
- **PART 6**, finding it in the wild.
- **PART 7**, the fixes that actually work.
- Glossary + next steps.

---

# PART 0, The Building Blocks

When *your browser* fetches `http://example.com`, the request comes from *your* machine on *your* network. You can only reach what you can reach.

When a *server* fetches a URL on your behalf, a "preview this link" feature, a webhook tester, an avatar-by-URL uploader, a PDF/screenshot renderer, an import-from-URL, the request comes from the **server's** machine on the **server's** network. And that network almost always contains things you were never meant to touch:

- the server's own **loopback** (`127.0.0.1`) where admin-only/internal services bind;
- other hosts in the **private VPC** (databases, queues, internal APIs);
- the **cloud metadata service** at `169.254.169.254`, which can hand out IAM credentials.

**SSRF is making the server fetch a URL of *your* choosing, so you borrow its network position.** You don't get to run code on the server (that's RCE); you get to make *requests as* the server.

---

# PART 1, The One Idea

> **If a server fetches a URL you control, you can aim that fetch at the server's own internal/loopback/metadata surface.**

The vulnerable shape:

```python
@app.post("/api/fetch")
def fetch():
    url = request.json["url"]
    r = requests.get(url)          # ← server requests whatever you give it
    return {"headers": dict(r.headers), "preview": r.text[:400]}
```

Nothing here restricts *where* `url` points. So `url = "http://127.0.0.1:9000/flag"` makes the *server* ask its own loopback for the flag and hand you the answer.

---

# PART 2, Detection & Confirmation

## 2.1 Spotting the sink

Any feature where you supply a URL/host and the server reaches out:

- link previews, "unfurl," webhook/callback testers
- avatar/image/file "import from URL"
- PDF/HTML-to-image renderers (headless browsers)
- XML/SVG/`<img>` parsers that follow external refs (also → XXE)
- "health check this endpoint," "validate this feed/RSS," S3/cloud import

## 2.2 Confirm it's really the server requesting

Point it at a host *you* control and watch for the hit:

```bash
# listener on your box
nc -lvnp 80
# or a logging canary
# then make the app fetch  http://YOUR_IP/ssrf-test
```

A request arriving from the **server's** egress IP (not yours) = confirmed SSRF. Collaborator/interactsh/`webhook.site` work when you don't have a public listener.

## 2.3 The quick internal probe

If you can't set up a listener, the error oracle still tells you a lot. Compare responses:

- `http://127.0.0.1:1/` → *connection refused* (server tried, nothing there)
- `http://127.0.0.1:80/` → a real response, or a different error
- a blocked string → *"blocked by policy"* (a filter, not a network result)

The moment the error changes from a *policy* message to a *network* result, you've reached the point where the server is actually dialing out, now it's about *where*.

---

# PART 3, The Target Map (what to point it at)

1. **Loopback services**, `http://127.0.0.1:PORT/`. Admin panels, debug endpoints, databases with HTTP, metrics. Scan common ports (80, 443, 3000, 5000, 6379, 8000-9000, 8500, etc.). This is where ORBIT DISPATCH's `:9000/flag` lived.
2. **Cloud metadata (the crown jewel)**:
   ```
   AWS   http://169.254.169.254/latest/meta-data/
         http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>   → temp AWS keys
         http://169.254.169.254/latest/user-data                                   → bootstrap scripts/secrets
   GCP   http://metadata.google.internal/computeMetadata/v1/   (needs header Metadata-Flavor: Google)
   Azure http://169.254.169.254/metadata/instance?api-version=2021-02-01  (needs header Metadata: true)
   ```
   On AWS, stealing the role's temp credentials is often game over. (In this CTF IMDS was reachable and proved the bug, but the flag was deliberately placed on a loopback service instead.)
3. **Private VPC neighbours**, internal APIs, Redis/Memcached (via `gopher://` for raw protocol injection if allowed), Elasticsearch, Kubernetes API (`https://10.0.0.1/`, kubelet `:10250`).
4. **Alternate schemes** (if not filtered): `file://` (read files), `gopher://` (speak arbitrary TCP → Redis/SMTP), `dict://`, `ftp://`.

---

# PART 4, Filter Bypasses, by Family

Defenders usually block "localhost/127.0.0.1/169.254.169.254" somehow. Each family below exploits a different weakness in *how* they block.

## 4.1 Alternate IP encodings (beats string matches)

All of these are `127.0.0.1`:

| Form | Example |
|---|---|
| Decimal (32-bit int) | `http://2130706433/` ← the ORBIT DISPATCH win |
| Hex | `http://0x7f000001/` |
| Octal | `http://0177.0.0.1/` |
| Short | `http://127.1/` |
| Mixed | `http://0x7f.1/` |
| IPv6 loopback | `http://[::1]/` |
| IPv6-mapped | `http://[::ffff:127.0.0.1]/` |
| "0" trick | `http://0/` (→ 0.0.0.0 → loopback on many stacks) |

**Why it works:** the filter compares the *text* `127.0.0.1`; the networking stack parses *any* of these to the same address. Same for metadata: `http://2852039166/` is `169.254.169.254`.

## 4.2 DNS tricks (beats static host lists)

- **Attacker domain → loopback**: `http://127.0.0.1.nip.io/`, `localtest.me`, or your own `A` record pointing at `127.0.0.1`.
- **DNS rebinding**: a domain that resolves to your IP on the *first* lookup (passes validation) and to `127.0.0.1` on the *second* lookup (the actual connection). Beats "resolve-then-check" that doesn't pin the IP.

## 4.3 Parser confusion in the URL itself (beats naive host extraction)

- Credentials/`@`: `http://expected.com@127.0.0.1/` (host is after the `@`).
- Fragment/`#`: `http://127.0.0.1#@expected.com/`.
- Backslashes, extra slashes, whitespace, case: different libraries parse `http://127.0.0.1\t`, `http:////127.0.0.1`, `http://127.0.0.1%2F..` differently. Mismatch between the *validator's* parser and the *fetcher's* parser = bypass.

## 4.4 Redirects (beats "validate the initial URL only")

Point at a URL *you* control that returns `301/302 → http://169.254.169.254/...`. If the fetcher follows redirects and only validated the first URL, it follows you right into the metadata service.

## 4.5 Scheme bypass

If `http`/`https` are allowlisted but the parser is loose: `HtTp://`, `http:/\/\`, or protocol-relative `//127.0.0.1`.

The ORBIT DISPATCH defender used **4.1's** weakness: a literal-string blocklist. Decimal `2130706433` was never in it.

---

# PART 5, Blind SSRF & Escalation

- **Blind** (no response shown): use timing (`refused` is fast, filtered is slow), DNS/HTTP out-of-band (does your canary get a hit?), and error differences as oracles.
- **Protocol smuggling**: `gopher://` lets you write raw bytes to a TCP port, craft a Redis `SET`/`SLAVEOF` or an SMTP email, turning read-only SSRF into writes/RCE.
- **Chaining**: SSRF → steal IAM creds from IMDS → use the AWS API → read S3/secrets. Or SSRF → internal admin panel → the real objective. The fetch is the foothold, not the finish.

---

# PART 6, Identifying This in the Wild

## 6.1 Code review

```bash
# Python
grep -rnE 'requests\.(get|post)\(|urllib\.request|httpx\.|urlopen\(' .
# Node
grep -rnE 'axios\(|fetch\(|http\.get\(|got\(|request\(' .
# look for the argument coming from user input, with no host validation nearby
```

Red flags: the URL/host argument is user-controlled; redirects followed by default; no IP-range check; validation done on the *string* before parsing.

## 6.2 Black box

- Enumerate every URL/host-taking field (§3.1). For each: canary callback to confirm, then walk the target map (loopback scan, metadata, redirects, encodings).

## 6.3 Severity

High-to-critical in cloud: a single SSRF that reaches IMDS can leak credentials and cascade into full account compromise. Even without cloud, internal admin access is usually severe.

---

# PART 7, The Fixes That Actually Work

1. **Validate the resolved IP, not the string.** Resolve the hostname, reject if the address is loopback/private/link-local/reserved. Do this with a proper IP library, not regex.
2. **Pin the connection to the validated IP.** Resolve once; connect to *that* IP; this defeats DNS rebinding/TOCTOU. (Libraries/wrappers exist; or use a vetting proxy.)
3. **Disable or re-validate redirects.** Every hop must pass the same IP check.
4. **Allowlist** schemes (`http`/`https` only) and, where possible, destination hosts/domains. Deny `file`, `gopher`, `dict`, `ftp`.
5. **Egress firewall.** The app's network namespace should not be able to reach `169.254.169.254`, internal admin ports, or the wider VPC. Default-deny egress.
6. **Harden metadata.** AWS: enforce **IMDSv2** (session-token required, so a plain SSRF GET can't read creds) and set hop limit to 1.
7. **Don't trust network position for authz.** The internal `/flag` service should still authenticate callers. "Only reachable from loopback" is not an access control once SSRF exists.

---

# Glossary

- **SSRF**, Server-Side Request Forgery; coercing a server to make requests you choose.
- **Loopback**, `127.0.0.0/8` / `::1`; the machine talking to itself; where internal-only services bind.
- **IMDS**, Instance Metadata Service (`169.254.169.254`); hands out instance info and, via IAM, temporary cloud credentials.
- **Link-local**, `169.254.0.0/16`; includes the metadata address.
- **DNS rebinding**, serving different DNS answers across lookups to pass validation then connect somewhere else.
- **Gopher smuggling**, using `gopher://` to write arbitrary bytes to a TCP service.
- **Blind SSRF**, SSRF where the response isn't returned to you; exploited via out-of-band / timing oracles.

# Where to Go Next

- Stand up the vulnerable fetcher (`requests.get(user_url)`), hit it with `http://2130706433/`, scan your own loopback, then add resolve-and-pin validation and watch every bypass in Part 4 die.
- Pair this with the dojo's **relicsociety-xxe** guide, XXE is "SSRF's cousin" (external entities can also fetch internal URLs/files).
- Learn `gopher://` Redis exploitation; it's the classic SSRF→RCE pivot.
