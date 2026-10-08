# Masterclass: IDOR & Predictable Object References, the Night Bus API, From Zero

**Companion to:** `nightbus-idor-writeup.md`

This box is an **API authorization** lesson: a receipt is "protected" by an object id that turns out to be a *hash of a public value*, so anyone can compute it. The guide teaches, from zero: what an IDOR is, how to recognise a *predictable* identifier (and a *fake* Mongo ObjectId), the method for proving "this id is a hash of that field," how to exploit it, and how to fix it properly. It generalises far beyond this one challenge, IDOR is #1 on the OWASP API Security Top 10.

---

## How to read this

- **Part 0**, objects, references, and what an API "id" is for.
- **Part 1**, the one idea: authorization by obscurity fails.
- **Part 2**, recognising predictable ids (sequential, hashed, fake ObjectIds).
- **Part 3**, the method: prove the id is derived, then derive the target's.
- **Part 4**, exploiting, and the "default-for-unknown" trap.
- **Part 5**, fixes (random ids *and* real authorization).
- **Glossary**.

---

# PART 0, Objects, References, and Ids

APIs expose **resources** (a booking, a user, a file) and give each one an **identifier** you put in the URL to fetch it: `GET /api/orders/<id>`. Two flavours of identifier show up here:

- **Reference**, a human-facing handle like `TOUR-2401` (sequential, meant to be shown).
- **Object**, the id the API actually looks up by, like `289290bbb72721bcad2f8717`.

The intent is usually: *references are public, but you need the (secret, unguessable) object to read the sensitive thing.* The bug is when the object turns out **not** to be secret, because it's **derivable** from the reference.

---

# PART 1, The One Idea

> **If access to a resource depends only on knowing its identifier, and that identifier is guessable or derivable, there is no access control at all.**

This is **IDOR** (Insecure Direct Object Reference), a.k.a. **BOLA** (Broken Object Level Authorization), OWASP API Security Top 10 #1. The server trusts "you named the object, so you may have it," instead of checking "*are you allowed* this object?" On Night Bus, the object is `sha256(reference)[:24]`, and the reference is printed in the listing, so the "secret" is public arithmetic.

---

# PART 2, Recognising a Predictable Identifier

When you see an opaque id, **question whether it's random**. Common predictable patterns:

| Pattern | Tell | Attack |
|---|---|---|
| **Sequential** | `/users/1001`, `/orders/42` | increment/decrement |
| **Encoded** | base64/hex that decodes to `{id:42}` | decode, change, re-encode |
| **Hashed public value** | fixed-length hex that *matches* `hash(field)` | compute `hash(other_field)` |
| **UUIDv1 / timestamped** | embeds MAC/time | narrow the search |
| **Real random (UUIDv4, CSPRNG)** | no structure, 122+ bits | not guessable, look elsewhere |

**Spotting a *fake* Mongo ObjectId:** a real ObjectId is 24 hex = `[4-byte unix time][5-byte random][3-byte counter]`. Decode the first 4 bytes as a timestamp:
```python
int("289290bb",16)  # 681775291  -> datetime ≈ 1991
```
A creation time in **1991** for a fresh booking is nonsense → the "ObjectId" is **synthetic**, i.e. generated some other way (like a hash). That single check redirected this whole solve away from "brute the counter" toward "it's a hash."

---

# PART 3, The Method: Prove Derivation, Then Derive

You're *given* one (reference, object) pair: `TOUR-2401 → 289290bbb72721bcad2f8717`. Treat it as a **known-plaintext** to reverse-engineer the id scheme.

**Step 1, hash the known reference every common way and compare:**
```python
import hashlib
target = "289290bbb72721bcad2f8717"
for ref in ("TOUR-2401","tour-2401","2401"):
    for algo in ("md5","sha1","sha256"):
        h = hashlib.new(algo, ref.encode()).hexdigest()
        if h[:len(target)] == target:
            print("MATCH:", algo, ref)   # -> sha256, TOUR-2401
```
`sha256("TOUR-2401")[:24]` matches. Scheme confirmed: **object = first 24 hex of SHA-256 of the reference.**

(If no plain hash matches, widen it: try `hash(ref+salt)`, `hmac(key,ref)`, HMAC you can't forge without the key, uppercase/lowercase, with/without prefix, or the reference as an integer. A plain unsalted hash is the common CTF case.)

**Step 2, derive the target.** The listing leaked the other reference (`next_reference: TOUR-2402`), so:
```python
hashlib.sha256(b"TOUR-2402").hexdigest()[:24]   # d9522cdd54fa82760ecb6f83
```

---

# PART 4, Exploiting + the "Default-for-Unknown" Trap

```bash
curl -s http://TARGET/api/orders/d9522cdd54fa82760ecb6f83
# {"receipt":"safctf{...}"}
```

One thing that nearly threw the solve: **every id returned the same `"Two seats, balcony level."`**, including obvious garbage. That made the endpoint look like it ignored its input. It didn't: unknown ids fall back to a **default receipt**, which happens to equal the first booking's. Lessons:
- A **uniform response** can be *masking* unknown ids behind a default, not proof the parameter is inert. Confirm your **id model** (sequence? hash? UUID?) before concluding "the id doesn't matter."
- Don't over-trust a brute-force that returns a plausible-but-constant answer, distinguish "valid default" from "real hit" (here, only the exact hash returns a *different*, flag-bearing receipt).

---

# PART 5, The Fixes

Two independent controls; a good API has **both**:

1. **Unguessable, non-derivable ids.** Never derive the lookup key from public data. Use a server-generated **random UUIDv4** or 128-bit token stored alongside the record. If you *must* map references to ids, use a keyed **HMAC** with a server secret (`hmac_sha256(secret, reference)`) so clients can't compute it, but this is a band-aid, not a substitute for #2.
2. **Object-level authorization (the real fix).** On every fetch, check that the **authenticated caller is entitled to that object**, don't return it just because they named it. Return `404`/`403` for anything they can't see (and the *same* status for "doesn't exist" vs "not yours" to avoid enumeration). This is the control OWASP calls **BOLA**, and it's missing here.

Also: **don't leak the next reference** (`next_reference: TOUR-2402`) to users who aren't allowed the next booking, that hand-delivered the input to the attack.

---

# Glossary

- **IDOR**, Insecure Direct Object Reference: accessing objects by manipulating their identifier, with no authorization check.
- **BOLA**, Broken Object Level Authorization; the API-era name for IDOR (OWASP API #1).
- **Reference**, a public, often sequential handle (`TOUR-2401`).
- **Object / resource id**, the key the API looks up by; should be unguessable.
- **Predictable identifier (CWE-340)**, an id derivable from observable data (sequence, hash of a public field).
- **ObjectId**, MongoDB's 12-byte id (`time|random|counter`); a nonsense timestamp signals a *fake* one.
- **Known-plaintext (here)**, a given (reference, object) pair used to reverse-engineer the id scheme.
- **HMAC**, keyed hash; derivable only with the server secret (a safer-than-plain-hash id, still no substitute for authz).

---

# Where to Go Next

- Practise on **PortSwigger → Access control / IDOR** labs and the **OWASP API Security Top 10 (BOLA)**.
- Build the habit: for every opaque id, ask *"sequential? encoded? hash of a field? truly random?"*, and when you hold one (reference, id) pair, try to **reproduce the id by hashing the reference**.
- Learn to read id internals: decode UUID versions, Mongo ObjectId timestamps, JWT/opaque tokens, structure tells you the attack.

The transferable idea: **an identifier is not a password.** If naming a resource is enough to read it, and the name is guessable or computable, the resource is public, authorization has to live in a check the server performs, not in the obscurity of an id.
