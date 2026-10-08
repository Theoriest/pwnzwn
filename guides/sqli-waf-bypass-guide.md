# Masterclass: SQL Injection Auth-Bypass & Beating a Keyword WAF, From Zero

The techniques behind THE VELVET ROOM, built up from nothing. You'll understand why string-built SQL is exploitable, how auth-bypass payloads actually evaluate, why WAFs keep losing to the same handful of tricks (especially whitespace), how to fingerprint a filter and craft a bypass methodically, and how to make the whole class of bug impossible.

> The dojo already has **poleposition-sqli** for vanilla SQLi. This guide focuses on the two things VELVET ROOM added: **beating a WAF** and **the post-auth crypto**. Read poleposition first if `'--` bypass is new to you.

## How to read this

- **PART 0**, how a login query works and where injection enters.
- **PART 1**, the one idea.
- **PART 2**, auth-bypass payloads and *why* they evaluate true.
- **PART 3**, fingerprinting a WAF.
- **PART 4**, the bypass families (whitespace, comments, case, encoding, logic) with reasoning.
- **PART 5**, the post-auth lesson: leaked keys.
- **PART 6**, finding it in the wild.
- **PART 7**, the real fix.
- Glossary + next.

---

# PART 0, The Building Blocks

A login usually runs a query like:

```python
q = "SELECT * FROM users WHERE username='" + u + "' AND password='" + p + "'"
cur.execute(q)
row = cur.fetchone()
if row: login_as(row)
```

The developer *intends* `u` and `p` to be **data** inside the quotes. But they're pasted into the query **string**, so if you include a quote you escape the data and start writing **SQL**. Same disease as SSTI, different interpreter: your input crosses from data into code.

With `u = alice`, `p = secret`:

```sql
SELECT * FROM users WHERE username='alice' AND password='secret'
```

With `u = admin' OR '1'='1`, `p = x`:

```sql
SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='x'
```

Now the `WHERE` is attacker-shaped logic, not a credential check.

---

# PART 1, The One Idea

> **If your input is concatenated into a SQL string, you don't submit a username, you submit a piece of the query.** Auth bypass = making the `WHERE` clause true without knowing the password.

---

# PART 2, Auth-Bypass Payloads, and Why They Work

## 2.1 Operator precedence is your friend

In `username='admin' OR '1'='1' AND password='x'`, SQL evaluates `AND` before `OR`:

```
username='admin'  OR  ( '1'='1' AND password='x' )
     TRUE         OR  ( ... )            = TRUE
```

If `admin` exists, the first operand is true and the whole row matches → you're `admin`, no password needed. (Even if `admin` didn't exist, `' OR '1'='1' --` makes *every* row match.)

## 2.2 The comment variant

`username = admin'--` turns the query into:

```sql
SELECT * FROM users WHERE username='admin'-- ' AND password='x'
```

Everything after `--` is a comment; the password check vanishes. (Note the engine: MySQL `-- ` needs a trailing space or use `#`; SQLite/Postgres use `--`; `#` is MySQL-only. VELVET ROOM was SQLite, and `--` was WAF-blocked, so comments were off the table and precedence, §2.1, carried the day.)

## 2.3 Know your engine

Fingerprint early, it decides comment syntax, string functions, and enumeration:

- Reflected error *"near X: syntax error"* → **SQLite**.
- `version()`, `::text` casts, `string_agg` → **PostgreSQL**.
- `@@version`, backtick identifiers, `#` comments → **MySQL/MariaDB**.

---

# PART 3, Fingerprinting a WAF

A WAF announces itself by treating *clean* and *injection-shaped* input **differently**:

- clean wrong login → "Invalid credentials"
- `' OR '1'='1` → "request could not be completed" / 403 / generic error

Different response to injection syntax = a filter in the path. Now enumerate it. Send **one token at a time** and classify each as blocked vs. allowed:

```bash
chk(){ r=$(curl -s -X POST .../login --data-urlencode "username=$1" --data-urlencode "password=x");
       echo "$r" | grep -qi "could not be completed" && echo "BLOCKED: $1" || echo "ok: $1"; }
chk "x OR 1=1"; chk "x UNION"; chk "x SELECT"; chk "x--"; chk "x||x"; chk "x AND 1=1"; chk "x'"; chk "x#"
```

Build a table of what's blocked (VELVET ROOM: `OR AND UNION SELECT || -- /*`) and what's allowed (`' # ; = '1'='1'`). The allowed set is your toolbox.

---

# PART 4, WAF Bypass Families

Each family beats a *different* assumption the filter made.

## 4.1 Whitespace smuggling (the VELVET ROOM win)

Filters often model SQL as **keywords separated by spaces** (`\bOR\b`, `OR\s+`). But SQL tokenizers accept *any* whitespace between tokens:

| Byte | Char |
|---|---|
| `0x09` | TAB |
| `0x0a` | newline (LF) |
| `0x0d` | carriage return |
| `0x0c` | form feed |
| `0x0b` | vertical tab (not always valid in every engine) |

So `admin'<TAB>OR<TAB>'1'='1` keeps the semantics but the WAF's space-anchored regex never matches. Also try **comments as separators** where allowed: `OR/**/1=1`, or SQL that needs no whitespace at all: `'OR'1'='1` (quotes adjoin the keyword).

> Practical gotcha: send the **real byte**, not its percent-text. The literal string `%0b` reaches the DB as `%` + `0b`, not a control char. Use `--data-urlencode` from a file containing the actual TAB, or `$'\t'` in a shell.

## 4.2 Comment insertion (beats keyword matching)

Inline comments break a keyword into pieces the regex won't recognize while the parser ignores them:

```
UN/**/ION  SE/**/LECT  O/**/R   -- MySQL also: /*!50000UNION*/ version-gated comments
```

(Only helps if `/* */` isn't itself blocked, VELVET ROOM blocked it, which is why whitespace was the path.)

## 4.3 Case & keyword-stripping tricks

- **Case**: `Or`, `oR`, `UnIoN`, beats case-sensitive filters. (VELVET ROOM's was case-*insensitive*, so this failed, always test it.)
- **Doubled keywords vs. a *stripping* WAF**: if the WAF *removes* the first match, `oORr` → `or`, `UNIUNIONON` → `UNION`. This only works against filters that **delete** rather than **reject**. VELVET ROOM *rejected*, so `oORr` just produced a SQLite syntax error, a reminder to confirm *which behaviour* the WAF has before relying on this.

## 4.4 Encoding (beats pre-normalization gaps)

URL-encoding (`%27` for `'`), double-URL-encoding (`%2527`), unicode/overlong forms, useful when the WAF inspects the raw bytes but the app decodes them later (or vice-versa). The bypass lives in the *mismatch* between what the filter sees and what the app executes.

## 4.5 Logic without blocked keywords

If `OR`/`AND`/`UNION` are all blocked, you can sometimes still bypass using only allowed operators: `=`, string equality, `||` (if allowed), nested quotes, or injecting into the *password* field instead. The principle: find *any* allowed construct that flips the `WHERE` to true.

**Meta-rule:** a WAF can only block patterns it imagined. The SQL grammar is bigger than any blocklist. Enumerate, then pick the family that beats the specific assumption they made.

---

# PART 5, The Post-Auth Lesson: Don't Trust the Client With Keys

Past the login, VELVET ROOM's vault "protected" the flag with AES, but shipped the **key in client JavaScript** (`vaultKey = base64("V4ultK3y12345678")`). Anything the browser needs to decrypt, the attacker also has. This is **client-side trust failure**:

- Keys, secrets, and "is_admin" decisions that live in JS/HTML are public.
- "Encrypted but the key is right there" = not encrypted.

Always check the page source, JS bundles, and API responses for embedded keys, tokens, feature flags, and hidden fields. Half the post-exploitation in web CTFs is reading what the client was handed.

---

# PART 6, Finding It in the Wild

## 6.1 Code review

```bash
grep -rnE "execute\(.*%|execute\(.*\+|execute\(f\"|\.query\(.*\+|cursor\.execute\(.*format" .
```

Any query assembled with `+`, `%`, `.format`, or an f-string and user input is suspect. The fix is a parameterised call with `?`/`%s` placeholders.

## 6.2 Black box

- Every input that could reach a query: login, search, filters, sort columns, IDs, headers, cookies.
- Probe with `'`, `"`, `)`, watch for errors/behaviour changes. Then auth-bypass payloads; then, if a WAF appears, fingerprint and bypass per Part 4.
- Automate carefully with `sqlmap --tamper=space2comment,charencode,...` once you understand the filter, but know *why* a tamper script works; this guide is that "why."

---

# PART 7, The Real Fix

1. **Parameterised queries / prepared statements.** Non-negotiable. The driver sends query text and data on separate channels; input can never become SQL. This kills the bug *and* makes the WAF unnecessary:
   ```python
   cur.execute("SELECT * FROM users WHERE username=? AND password_hash=?", (u, hashed))
   ```
2. **Hash passwords** (argon2/bcrypt); compare in app code, not in SQL.
3. **Least-privilege DB account** (no `FILE`, no DDL) to cap damage if something slips.
4. **Suppress DB errors** to clients; log them server-side.
5. **WAF only as defense-in-depth**, and if used, it must canonicalize whitespace/comments/encodings before matching, never rely on it as the control.
6. **Keep secrets server-side.** Do crypto behind authorization; never hand keys to the browser.

---

# Glossary

- **SQL injection**, user input parsed as SQL because it was concatenated into the query string.
- **Auth bypass**, injecting logic that makes the login `WHERE` true without valid creds.
- **WAF**, Web Application Firewall; pattern-matches requests for "bad" input.
- **Whitespace smuggling**, using TAB/newline/comment instead of space to dodge space-anchored filters.
- **Keyword stripping**, a WAF that *deletes* bad substrings (vs. rejecting), beatable with doubled keywords.
- **Parameterised query**, query text and data sent separately (`?` placeholders); the real fix.
- **Client-side trust failure**, relying on the browser to keep keys/secrets/decisions.

# Where to Go Next

- Build a SQLite login with string concatenation + a naive `OR`-blocking regex. Bypass it with a TAB, then with `'OR'1'='1`, then rewrite with `?` placeholders and watch both die.
- Read **dailyscoop-postgres-sqli** next for *UNION-based data extraction* (the other half of SQLi, reading arbitrary tables).
- Compare with **ssti-jinja2-rce** and **deepblue-llm**: the same "data becomes instructions" bug across three different interpreters.
