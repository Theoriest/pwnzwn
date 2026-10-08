# Masterclass: Mass Assignment & Key-Traversal, Writing Fields You Weren't Given, From Zero

The bug behind BACKSTAGE LEDGER. By the end you'll understand how "update your profile" turns into "make yourself an admin," why nesting and `../`-style keys defeat naive allowlists, how to find the one writable field that gates a privileged action, and how to fix it properly.

## How to read this

- **PART 0**, how an update endpoint usually merges your input.
- **PART 1**, the one idea.
- **PART 2**, classic mass assignment.
- **PART 3**, the BACKSTAGE LEDGER twist: a `../` key that escapes the allowed object.
- **PART 4**, finding & exploiting it.
- **PART 5**, fixes.
- Glossary + next.

---

# PART 0, The Building Blocks

An "update" endpoint takes a blob of fields and merges them into a stored object:

```python
for key, val in request.json.items():
    user[key] = val          # whatever you send becomes a user field
```

Convenient, and exactly the problem: the client decides *which* fields get written. If the object also holds authorization fields (`role`, `is_admin`, `balance`, `verified`), and the merge doesn't stop you touching them, you can set them. That's **mass assignment** (a.k.a. autobinding / object injection): the request is allowed to assign to object attributes it was never meant to.

---

# PART 1, The One Idea

> **If an update merges attacker-controlled keys into a server object, the attacker can write any field of that object, including the ones that decide privilege.** The only real defense is an allowlist of exactly which fields a user may set.

BACKSTAGE LEDGER gated `/api/settlement` on `user['role']=='producer'` and let `role` be written through the profile update. Set it, then settle.

---

# PART 2, Classic Mass Assignment

The textbook version: a signup/profile endpoint binds the whole request body to a model.

```http
PATCH /api/profile
{"display_name":"me","role":"admin"}      # role wasn't in the form, but the merge takes it
```

Rails `update(params[:user])`, Spring `@ModelAttribute`, Django `ModelForm` with `fields='__all__'`, Node `Object.assign(user, req.body)`, all have shipped this. The attacker just adds the privileged field (`role`, `isAdmin`, `account_balance`, `email_verified`, `owner_id`) to an otherwise-innocent update.

Developers "fix" it by restricting the allowed keys. BACKSTAGE LEDGER shows why a *shallow* restriction isn't enough.

---

# PART 3, The BACKSTAGE LEDGER Twist: `../` Key-Traversal

The developer locked PATCH down twice: the body may contain only `profile`, and each inner key is written into `user['profile']`. But one branch betrays it:

```python
if set(d)-{'profile'}: return result(False)       # body may ONLY have 'profile'
for key,val in d.get('profile',{}).items():
    if key.startswith('../'): user[key[3:]]=val     # ../X writes user[X]  ← escapes the profile!
    else: user['profile'][key]=val
```

A key beginning `../` has its prefix stripped and is written to the **parent** object (`user`) instead of the allowed child (`profile`). So the "you may only edit profile" guard is bypassed by a nested key that traverses up a level, the data-structure analogue of filesystem path traversal (`../` escaping a directory), just in a dict:

```bash
S="mysession"
curl -s -X PATCH "http://TARGET/api/profile" -H "X-Session: $S" \
  -H 'Content-Type: application/json' --data '{"profile":{"../role":"producer"}}'
# {"profile":{"theme":"night"},"role":"producer"}
curl -s -X POST "http://TARGET/api/settlement" -H "X-Session: $S"
# flag
```

The same idea appears as **prototype pollution** in JavaScript (`__proto__`/`constructor` keys escaping an object into its prototype) and as **deep-merge** bugs generally: any recursive merge that honors structure in attacker keys can be steered out of its intended container. Watch for `__proto__`, `constructor`, `prototype`, `../`, leading dots, and dotted paths (`a.b.c`) in keys.

---

# PART 4, Finding & Exploiting

## 4.1 Black box

1. **GET the object first** to learn its fields and find the privileged one (BACKSTAGE LEDGER's GET showed `role` sitting next to `profile`).
2. **Find the gated action**, what endpoint checks a field you don't control (`settlement` needs `role==producer`)?
3. **Try to write that field** through every update you have:
   - directly: `{"role":"producer"}`
   - nested: `{"profile":{"role":"producer"}}`
   - escaped: `{"profile":{"../role":"producer"}}`, `{"__proto__":{"role":"producer"}}`, `{"role.":"..."}`, dotted paths.
4. **Keep session identity stable** (same `X-Session`/cookie) so the written field persists into the privileged call.

## 4.2 Severity

Privilege escalation, account takeover, tampering with balances/ownership/verification. High whenever the writable field gates anything.

---

# PART 5, The Fixes

1. **Allowlist exact settable fields.** Enumerate them (`theme`, `display_name`) and ignore everything else, don't blocklist, don't strip-and-merge.
   ```python
   ALLOWED = {'theme','display_name'}
   for k,v in d.get('profile',{}).items():
       if k in ALLOWED: user['profile'][k]=v   # no escape branch, ever
   ```
2. **Separate authorization from the user-editable record.** `role`/privilege live where the update code can't reach, and are set by an admin flow, not a profile PATCH.
3. **Reject structured keys** outright: no `../`, no leading `.`, no `__proto__`/`constructor`, no dotted paths. Use a safe merge that treats keys as literal leaf names.
4. **Decide privilege server-side** on every sensitive action, from server-held state, never from a field the client could have written.
5. **Use real sessions**, signed/opaque tokens the server issues, not a client-chosen `X-Session` header.

---

# Glossary

- **Mass assignment**, binding a request body to object attributes, letting the client write fields it shouldn't.
- **Key-traversal**, a nested key (`../role`) that escapes its allowed container into a parent object.
- **Prototype pollution**, the JS form: `__proto__`/`constructor` keys escaping into the object prototype.
- **Allowlist**, permitting only an explicit set of fields; the real fix (vs. blocklisting bad ones).
- **Privilege field**, a stored attribute (`role`, `is_admin`) that gates sensitive actions.

# Where to Go Next

- Build an update endpoint with a recursive/`../`-honoring merge, escalate `role`, then rewrite it with a flat allowlist and watch it die.
- Related in this dojo: **stageworks** (self-asserted session tags), **vinylvault** (client-set privilege header), **nightbus** (IDOR), all variants of "the client supplied a value the server trusted," and **touchline-path-traversal** for the filesystem version of the same `../` escape.
