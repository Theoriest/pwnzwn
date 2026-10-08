# Masterclass: LDAP Injection, the ROSTER HQ Login Bypass, Explained From Zero

**Companion to:** `rosterhq-ldap-injection-writeup.md`

The writeup tells the story of *how the box fell*. This is the **masterclass**: it explains *every technique used*, how to **build the payloads yourself** from first principles, how to **tell this bug apart from SQL injection**, and the **actual vulnerabilities** (plus how to fix them and how to build a lab to practise). I assume you've never heard of LDAP. By the end you should be able to recognise an LDAP-backed login, craft a filter-breakout by hand, and explain exactly why each payload authenticates you.

---

## How to read this

- **Part 0**, what LDAP even is, and how a login uses it.
- **Part 1**, the one idea behind all injection, pointed at LDAP.
- **Part 2**, LDAP *search filters*: the mini-language you'll be injecting into.
- **Part 3**, the vulnerability: how an LDAP login gets built wrong.
- **Part 4**, building the exploit payloads by hand (and *why* each ROSTER HQ payload worked).
- **Part 5**, SQLi vs LDAPi: reading the clues (what told us it was LDAP).
- **Part 6**, everything else I used: the length-gate gotcha, Flask session cookies, post-auth directory discovery, cookie handling in curl.
- **Part 7**, the real fixes.
- **Part 8**, build-your-own vulnerable lab to practise.
- **Glossary**.

---

# PART 0, What Is LDAP?

**LDAP** (Lightweight Directory Access Protocol) is how applications talk to a **directory service**, a database optimised for *looking things up*, especially **users**. If you've heard of **Active Directory** (Microsoft) or **OpenLDAP**, those are directory servers you query with LDAP. Companies use it as the central list of "who works here, what are their usernames, groups, emails."

The data is a **tree** of **entries**. Each entry has a **DN** (Distinguished Name, its unique path, like a file path) and **attributes** (key→value). A user entry might be:

```
dn: uid=admin,ou=players,dc=rosterhq,dc=local
uid: admin
cn: Admin User
userPassword: s3cr3t
```

- `dn:`, the entry's full address in the tree.
- `uid`, `cn`, `userPassword`, attributes.

**How a login uses it.** The app typically does one of two things:
1. **Search-then-compare:** build a filter to find the user *and* check the password in one search: `(&(uid=admin)(userPassword=s3cr3t))`. If the search returns an entry → logged in.
2. **Bind:** find the user's DN, then try to *authenticate* (LDAP "bind") with that DN + the supplied password.

ROSTER HQ used the **search** style (style #1), and that's what makes it injectable, because our input goes into that filter string.

---

# PART 1, The One Idea (again, in LDAP clothes)

Every injection bug is the same sentence:

> **The program mixed untrusted input with instructions, and an interpreter couldn't tell which was which.**

For SQL injection, the interpreter is the SQL engine. For **LDAP injection**, the interpreter is the **LDAP filter parser**. The app pastes your `username` into a filter string; if you include **filter syntax** (`( ) * & |`), the LDAP server reads it as *structure*, not *data*, and you rewrite the question being asked. "Find the user named X with password Y" becomes "find any user at all."

---

# PART 2, LDAP Search Filters: the Language You Inject Into

You *must* understand filter syntax to craft payloads. It's small and fully parenthesised (prefix/Polish notation).

### 2.1 The atoms
A single condition is `(attribute=value)`:
```
(uid=admin)         # uid equals "admin"
(userPassword=s3cr3t)
```

### 2.2 The wildcard `*`
`*` matches anything:
```
(uid=*)             # ANY entry that has a uid (i.e. every user)
(uid=adm*)          # uid starting with "adm"
```

### 2.3 Boolean operators go in FRONT (prefix)
Unlike SQL's `A AND B`, LDAP writes the operator first, then the operands, each parenthesised:

| Operator | Meaning | Example |
|---|---|---|
| `&` | AND | `(&(uid=admin)(userPassword=s3cr3t))` = uid is admin **and** password matches |
| `\|` | OR | `(\|(uid=admin)(uid=guest))` = uid is admin **or** guest |
| `!` | NOT | `(!(uid=admin))` = uid is **not** admin |

So the typical login filter:
```
(&(uid=<username>)(userPassword=<password>))
```
reads: *AND( uid = username, userPassword = password )*, return the entry only if **both** match.

### 2.4 The two magic "constants"
These matter for payloads:
- `(&)`, an AND with **no conditions** = **always TRUE** (the "absolute true" filter).
- `(|)`, an OR with no conditions = **always FALSE**.

`(&)` is the LDAP equivalent of SQL's `OR 1=1`. Remember it.

### 2.5 The metacharacters you weaponise
Characters that are *structure*, not data: `(` `)` `*` `&` `|` `!` `\` `=`. If the app doesn't escape them in your input, you control the filter's shape.

---

# PART 3, The Vulnerability: an LDAP Login Built Wrong

Here's the vulnerable pattern (what ROSTER HQ effectively did):

```python
# VULNERABLE — username pasted straight into the filter
filt = f"(&(uid={username})(userPassword={password}))"
results = conn.search(base_dn, filt)
if results:
    login_as(username)        # entry found → "authenticated"
```

Two design mistakes:
1. **String-building the filter** from raw input (no escaping of `)(*&|`).
2. **Search-and-compare auth**, presence of a matching entry *is* the auth decision, so if we make the filter match *anything*, we're "in" (and the app logged us in as `admin`, likely the first/only match or a fixed display name).

The password-length check (`len(password) >= 4`) sat in front of this but only gated **length**, not **content**, so it never stopped a malicious **username**.

---

# PART 4, Building the Payloads By Hand

Goal: make `(&(uid=<INJECT>)(userPassword=<pw>))` **always match**, with no valid password. We inject into `<INJECT>` (the username). The core trick: use `)` to **close** the `uid=` clause early, add our own filter logic, then use `(` to **re-balance** the parentheses so the whole thing still parses.

Let `pw = aaaa` (just needs length ≥ 4 to clear the gate).

### 4.1 Payload A, `admin)(&)`
Substitute into the template:
```
(&(uid=admin)(&))(userPassword=aaaa))
```
Parse it: the first complete filter is `(&(uid=admin)(&))` = **AND( uid=admin, TRUE )** = matches the admin entry **regardless of password**. The trailing `(userPassword=aaaa))` is leftover that the parser ignores (or the app only uses the first filter). ✅ You're admin. This is the cleanest one, `(&)` = "always true" is doing the work.

### 4.2 Payload B, `*)(uid=*))(|(uid=*`
Substitute:
```
(&(uid=*)(uid=*))(|(uid=*)(userPassword=aaaa))
```
This produces **two** top-level filters back to back:
- `(&(uid=*)(uid=*))` → AND( any uid, any uid ) → matches **every** user.
- `(|(uid=*)(userPassword=aaaa))` → OR( any uid, password=aaaa ) → also matches everyone.

Either way the search returns entries → login succeeds. This is the "universal" LDAP-injection payload you'll see in cheat sheets; it's built to stay balanced no matter the exact template.

### 4.3 Payload C, `*)(|(uid=*))`
Substitute:
```
(&(uid=*)(|(uid=*)))(userPassword=aaaa))
```
`(&(uid=*)(|(uid=*)))` = AND( any uid, OR(any uid) ) = matches everyone; trailing ignored. ✅

### 4.4 Why `*` alone FAILED
Payload `*` → `(&(uid=*)(userPassword=aaaa))` = "any user **whose password is literally `aaaa`**." Nobody's password is `aaaa`, so **no match → Failed.** The lesson: a bare wildcard still has to satisfy the *password* clause. You need to **break out** and neutralise that clause (close it, OR it away, or make it always-true), which is exactly what A/B/C do and `*` doesn't.

### 4.5 The recipe (generalise it)
1. **Close** the current clause: `)`
2. **Inject** an always-true condition or wildcard: `(&)` or `(uid=*)`
3. **Re-balance / swallow** the rest: add `(` ...filter... so parens match, or arrange trailing text to be ignored.

That's the same three-move shape as the SQL quote-breakout from other boxes (`'` → `OR 1=1` → `--`), just with LDAP's parens instead of quotes and comments.

---

# PART 5, Was It SQL or LDAP? Reading the Clues

This is the judgement that actually solved it. How to decide which injection you're facing:

| Signal | SQL-ish | LDAP-ish |
|---|---|---|
| Vocabulary in the app | "database", "record", "query" | **"directory"**, "entry", "OU", "bind" |
| What broke it | `'` quote, `--` comment, `UNION` | `)` `(` `*` `&` `|` parens/wildcards |
| ROSTER HQ evidence |, | **"Log in to Directory Failed"**, "operations **directory**", `' OR '1'='1'` did nothing, but `)(&)` worked |

**The meta-skill:** when standard SQLi auth-bypass does *nothing* on an obvious login, don't just conclude "parameterised, give up." Ask *what kind of datastore is this?* The app's own words ("Directory") told us. Other datastores inject too, LDAP, XPath, NoSQL/Mongo (`[$ne]`), etc. Match the payload language to the backend.

---

# PART 6, The Supporting Techniques

### 6.1 The length-gate gotcha (a testing lesson)
Early SQLi tests used `password=x` and were rejected with *"Password length not acceptable"*, they **never reached the query.** If you conclude "not injectable" while your payload is dying at a validation check, you've drawn the wrong conclusion. **Make sure your payload actually reaches the vulnerable code** (here: password length ≥ 4) before ruling injection out. A failed exploit is often a *delivery* problem, not a *theory* problem.

### 6.2 Flask signed session cookies
After login we got:
```
Set-Cookie: session=eyJ1c2VybmFtZSI6ImFkbWluIn0.<timestamp>.<signature>
```
That first segment is **base64 JSON**:
```bash
echo 'eyJ1c2VybmFtZSI6ImFkbWluIn0' | base64 -d   # → {"username":"admin"}
```
Flask sessions are **signed, not encrypted**, you can *read* them freely, but not *change* them without the app's `SECRET_KEY`. Here we didn't need to forge anything (the LDAP bypass set the session for us), but if a box ever needs you to become another user, the research path is `flask-unsign` (decode, and brute/guess the secret to re-sign a tampered cookie). Reading it was still useful: it *confirmed* the bypass authenticated us specifically as `admin`.

### 6.3 Post-auth directory discovery
Your original hypothesis ("directory discovery") came true *after* auth: the logged-in page linked `/config-update`, `/audit-export`, `/logout`. **Authenticated enumeration** matters, the real functionality (and the flag) lived behind the login, not in the public surface. Always re-enumerate once you hold a session; protected routes return `403`/redirect when you're logged out (as `/audit-export` did) and only reveal themselves with the cookie.

### 6.4 Driving it with curl (so you can replay anything)
- `-c jar` / `-b jar`, **save** cookies from responses / **send** them on requests (this is how you stay "logged in" between calls).
- `--data-urlencode 'username=...'`, send the exact bytes of a payload full of `)(*&|` without your shell or curl mangling them (same discipline as sending shell-metachar payloads safely).
- `-i` show headers (to catch the `302` + `Set-Cookie`), `-L` follow the redirect, `-o /dev/null -w '%{http_code}'` to diff status codes quickly.

---

# PART 7, The Actual Vulnerabilities & Fixes

### 7.1 LDAP Injection (CWE-90), the real bug
**Fix 1, escape filter input (RFC 4515).** Every untrusted value in a filter must have its metacharacters escaped:
```
(  → \28     )  → \29     *  → \2a     \  → \5c     NUL → \00
```
Most libraries provide this (e.g. `ldap3.utils.conv.escape_filter_chars`, `ldap.filter.escape_filter_chars`). Escaped, `admin)(&)` becomes the literal string `admin\29\28\26\29`, a username that simply doesn't exist, not filter structure.

**Fix 2 (better), authenticate by bind, not by search-compare.** Search for the user DN with an *escaped* filter, then attempt an LDAP **bind** using that DN and the supplied password. The password is then checked by the LDAP server's auth, not by string-matching inside a filter, so filter injection can't substitute for knowing the password.

```python
# Safer shape
safe = escape_filter_chars(username)
dn = find_user_dn(f"(uid={safe})")          # escaped search
if dn and conn.rebind(dn, password):        # real bind = real auth
    login_as(username)
```

### 7.2 Validation theatre (the length gate)
A length check isn't security. **Validate content/shape** (allow-list characters for a username, reject filter metacharacters) and never rely on size limits to stop injection.

### 7.3 Broken access control (CWE-284)
`/audit-export` handed the flag to any authenticated session. Sensitive exports should enforce real **authorization** (role/permission), not merely "is some session present."

---

# PART 8, Build Your Own LDAP-Injection Lab (to practise)

The fastest way to *own* this technique is to build the vulnerable thing and attack it:

1. **Stand up a directory:** run OpenLDAP in Docker (`osixia/openldap`) and add a couple of user entries (`uid=admin`, `userPassword=...`).
2. **Write the vulnerable login** (Flask + `ldap3`), deliberately string-building the filter:
   ```python
   filt = f"(&(uid={request.form['username']})(userPassword={request.form['password']}))"
   ok = conn.search('ou=players,dc=lab,dc=local', filt)
   ```
3. **Attack it** with `admin)(&)` and `*)(uid=*))(|(uid=*)` and watch it let you in.
4. **Fix it** two ways, `escape_filter_chars`, then switch to bind-auth, and watch each payload die.

Breaking and then fixing your own code teaches this faster than any writeup.

---

# Glossary

- **Active Directory / OpenLDAP**, common directory servers you query with LDAP.
- **Attribute**, a key→value on an entry (`uid`, `cn`, `userPassword`).
- **Bind**, authenticating to the LDAP server (e.g. as a user DN + password). Binding to auth is the safe alternative to search-compare.
- **DN (Distinguished Name)**, an entry's unique path in the directory tree.
- **Directory service**, a database optimised for looking up users/objects; spoken to via LDAP.
- **Filter**, the LDAP query language, fully parenthesised and prefix-operator (`(&(a=1)(b=2))`).
- **`(&)` / `(|)`**, always-true / always-false filters; `(&)` is LDAP's `OR 1=1`.
- **Flask signed session**, a cookie holding base64 JSON, signed (not encrypted) with the app's `SECRET_KEY`; readable by anyone, forgeable only with the key.
- **LDAP**, Lightweight Directory Access Protocol.
- **LDAP injection (CWE-90)**, rewriting an LDAP filter via unescaped input (`)(*&|`), e.g. to bypass a login.
- **RFC 4515**, the spec defining filter syntax and the escaping rules (`\28`, `\29`, `\2a`, ...).
- **Search-and-compare auth**, logging a user in because a filter *found* a matching entry; injectable, unlike bind-auth.
- **Wildcard `*`**, matches any value in an LDAP filter.

---

# Where to Go Next

- Read the **OWASP LDAP Injection Prevention Cheat Sheet** and **RFC 4515** (filters + escaping).
- Add LDAP payloads to your kit from **PayloadsAllTheThings → LDAP Injection**.
- Practise telling backends apart: when a login resists SQLi, ask "SQL? LDAP? XPath? NoSQL?" and switch payload languages, the app's own vocabulary ("directory", "document", "record") is often the tell.
- Keep the testing discipline from this box: **confirm your payload reaches the vulnerable code** (mind validation gates), and **use a cookie jar** so you can replay the authenticated state at will.

The transferable idea, one more time: **an injection's language must match its interpreter.** SQLi speaks quotes and `--`; LDAPi speaks parens and `*`. Read the app to learn which interpreter you're really talking to.
