# Masterclass: HTTP Parameter Pollution, When One Request Is Two Identities, From Zero

The bug behind VELVET REHEARSAL. By the end you'll understand what happens when a request carries the *same* parameter more than once, why different stacks disagree about which value "wins," how to turn that disagreement into an auth bypass or a logic break, and how to shut it down.

## How to read this

- **PART 0**, what duplicate parameters even do.
- **PART 1**, the one idea.
- **PART 2**, how each stack resolves duplicates (the table you actually need).
- **PART 3**, the VELVET REHEARSAL pattern, generalized.
- **PART 4**, finding and exploiting it.
- **PART 5**, fixes.
- Glossary + next.

---

# PART 0, The Building Blocks

An HTTP request can carry the same parameter name twice:

```
POST /api/recovery?member=visitor@studio.test&member=director@studio.test
```

There's no rule in HTTP about what that *means*. Each framework picks its own answer: take the first, take the last, or hand the code a **list** of all of them. That ambiguity is the whole bug class. **HTTP Parameter Pollution (HPP)** is supplying a parameter multiple times so that two parts of the system, or the app and the attacker, resolve it to *different* values.

---

# PART 1, The One Idea

> **If the same parameter is read in more than one place, and those places pick different occurrences (first vs. last vs. the whole list), you can make one request be two different values at once.**

VELVET REHEARSAL read `member` as a list and pulled `raw[0]` for "who may see the token" and `raw[-1]` for "who the token belongs to." One request → visitor (for delivery) *and* director (for ownership).

---

# PART 2, How Stacks Resolve Duplicates

For `a=1&a=2`:

| Stack / API | Result |
|---|---|
| PHP (`$_GET['a']`), Rails | `2` (last) |
| Python Flask `request.args.get('a')` | `1` (first) |
| Flask `request.args.getlist('a')` | `['1','2']` (the whole list) |
| Express `req.query.a` | `['1','2']` (array!) |
| ASP.NET `Request.QueryString['a']` | `"1,2"` (comma-joined) |
| Java servlet `getParameter` / `getParameterValues` | first / all |

The danger multiplies when **two different components** parse the same request, a WAF that checks the *first* value and an app that uses the *last*, a proxy vs. a backend, or (as in VELVET REHEARSAL) two lines of the *same* handler indexing opposite ends of the list.

---

# PART 3, The VELVET REHEARSAL Pattern, Generalized

```python
raw = request.args.getlist('member')
target    = raw[-1]    # a security decision from the LAST value
recipient = raw[0]     # a different security decision from the FIRST value
```

Two security-relevant facts (who owns the issued token; who is allowed to receive it) are derived from the *same* repeated input, at different indices. The attacker controls every index, so they satisfy both checks with one request. The general shape to hunt for: **the code calls `getlist`/`getParameterValues` and then indexes it more than once** (`[0]`, `[-1]`, `[1]`), using each for a different purpose.

Other classic HPP wins:
- **WAF/validator vs. app mismatch**: the filter inspects `a=benign`, the app uses the second `a=<payload>`.
- **Authorization vs. action**: an `id` checked for ownership on the first occurrence, used for the operation on the second.
- **Caching/routing keys** computed from one occurrence, business logic from another.

---

# PART 4, Finding & Exploiting

## 4.1 Black box

- Duplicate every interesting parameter: `?id=1&id=2`, `&user=me&user=admin`, in query *and* body, and mixed (query `a=1` + body `a=2`).
- Watch for a response that reflects an *unexpected* value, a changed authorization outcome, or a filter that stopped firing.
- Try order both ways (`admin` first vs. last), you don't know which index each code path reads.
- Mix channels: some frameworks prefer body over query or vice-versa; polluting across them hits proxy/app splits.

## 4.2 The VELVET REHEARSAL solve

```bash
# visitor first (passes the "who may see the mailbox" check),
# director last (becomes the token's owner)
RESP=$(curl -s -X POST "http://TARGET/api/recovery?member=visitor@studio.test&member=director@studio.test")
TOKEN=$(echo "$RESP" | python3 -c "import sys,json;print(json.load(sys.stdin)['mailbox'][0]['token'])")
curl -s -X POST "http://TARGET/api/entry" -H 'Content-Type: application/json' --data "{\"token\":\"$TOKEN\"}"
```

---

# PART 5, The Fixes

1. **Read a single value deliberately.** Use `request.args.get('member')` (first) and *mean* it; if you must accept a list, reject anything with more than one value for a security-relevant field.
2. **Never derive two decisions from the same input at different indices.** Who-owns and who-may-see are separate inputs with separate validation.
3. **Don't return recovery/sign-in tokens in a response at all.** Deliver them out-of-band to the address that owns them; then there's nothing for pollution to leak.
4. **Normalize before the WAF and the app agree.** If a filter and the app both parse the request, make them canonicalize duplicates identically (or reject duplicates outright).
5. **Validate server-side ownership**, not a client-echoed identity.

---

# Glossary

- **HTTP Parameter Pollution (HPP)**, sending a parameter more than once so components resolve it to different values.
- **`getlist` / `getParameterValues`**, APIs that return *all* occurrences; dangerous when indexed more than once.
- **First-vs-last divergence**, a filter/validator reads one occurrence, the app another.
- **Broken password recovery**, a sign-in/reset token reaching someone other than the account owner.

# Where to Go Next

- Build a Flask endpoint that `getlist`s a param and indexes `[0]` and `[-1]` for two decisions; pollute it and watch one request be two identities. Fix it by reading a single value and delivering tokens out-of-band.
- Related in this dojo: **touchline-path-traversal** (how the shared source leaked) and **backstageledger-mass-assignment** (another "the client controlled a field two layers disagreed about").
