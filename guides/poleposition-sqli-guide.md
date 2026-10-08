# Masterclass: SQL Injection Auth Bypass, the POLE POSITION Login, From Zero

**Companion to:** `poleposition-sqli-writeup.md`

The box was simple, but SQL injection is *the* foundational web bug, worth understanding completely. This guide explains what SQL is, how a login query works, exactly how the `admin'-- -` payload rewrites that query, why `' OR '1'='1` sometimes fails, how to tell SQLi apart from LDAP/NoSQL, and how to find and fix it. From zero.

---

## How to read this

- **Part 0**, what SQL is and how a login uses it.
- **Part 1**, the one idea behind injection (again).
- **Part 2**, the vulnerable query, drawn out.
- **Part 3**, building the payload by hand (`admin'-- -` and friends), and why `' OR '1'='1` failed here.
- **Part 4**, reading the clues: SQL vs LDAP vs NoSQL.
- **Part 5**, going beyond auth bypass (UNION, blind), a map for harder boxes.
- **Part 6**, the real fix.
- **Glossary**.

---

# PART 0, What Is SQL, and How Does a Login Use It?

**SQL** (Structured Query Language) is how apps talk to relational databases (MySQL, PostgreSQL, SQLite...). Data lives in **tables** of rows and columns. A `users` table might be:

| id | username | password |
|----|----------|----------|
| 1  | admin    | s3cr3t   |
| 2  | bob      | hunter2  |

To log you in, the app asks the database "is there a row matching this username and password?" with a **query**:
```sql
SELECT * FROM users WHERE username='admin' AND password='s3cr3t';
```
If a row comes back → you're authenticated. The bug is in **how the app builds that query string.**

---

# PART 1, The One Idea (again)

Every injection is the same sentence:

> **The program mixed untrusted input with instructions, and an interpreter couldn't tell which was which.**

Here the interpreter is the **SQL engine**. The app pastes your `username` into the query text; if you include SQL syntax (a quote `'`, a comment `--`), the engine reads it as *structure*, not *data*, and you rewrite the query.

---

# PART 2, The Vulnerable Query

POLE POSITION effectively did this (the classic mistake):
```python
# VULNERABLE — input concatenated into SQL text
q = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
row = db.execute(q)
if row: login_as(row.username)
```
With normal input `username=admin`, `password=s3cr3t`:
```sql
SELECT * FROM users WHERE username='admin' AND password='s3cr3t'
```
Your username sits **inside single quotes**. The only thing keeping it as "data" is those quotes, and a `'` character ends them. That's the whole door (same hinge as the command-injection boxes, different interpreter).

**The behaviour that set the objective:** this app logged *anyone* in and only printed the flag for the **admin** user ("Flag at admin user"). So we don't need a password, we need the query to **return the admin row.**

---

# PART 3, Building the Payload By Hand

### 3.1 `admin'-- -` (what worked)
Set `username = admin'-- -`. Substituted:
```sql
SELECT * FROM users WHERE username='admin'-- -' AND password='x'
```
Read it the way the database does:
1. `username='admin'`, match the admin row.
2. `-- -`, **a comment.** Everything after it on the line is ignored, so `' AND password='x'` **disappears.**
3. Result: `SELECT * FROM users WHERE username='admin'` → returns admin, **no password check.** ✅

Why `-- -` and not just `--`? In **MySQL**, a `--` comment must be followed by **whitespace** (or end-of-line) to count. `-- -` is "dash dash space dash", guaranteed valid. Alternatives: `#` (MySQL), or `-- ` with a trailing space. (In SQLite/Postgres bare `--` works too; `-- -` is the portable habit.)

### 3.2 Why `' OR '1'='1` FAILED here
Set `username = ' OR '1'='1`, `password = x`:
```sql
SELECT * FROM users WHERE username='' OR '1'='1' AND password='x'
```
By SQL precedence (`AND` binds tighter than `OR`), this is `username='' OR ('1'='1' AND password='x')`. For a row to match, it needs `password='x'`, which no one has. So: **Login failed.** The lesson: a bare `OR '1'='1` has to coexist with the trailing `AND password=...`; when that spoils it, **comment the tail out** instead (`admin'-- -`). Commenting is more reliable than balancing.

### 3.3 The OR-bypass done right
If you *do* want the OR style, comment the rest too:
```
username = ' OR '1'='1'-- -
```
→ `...WHERE username='' OR '1'='1'-- -' AND password='x'` → `username='' OR '1'='1'` → every row matches (returns the first, often `admin`). Both approaches work; `admin'-- -` is cleanest when you want a *specific* user.

### 3.4 The three-move recipe (same as every injection)
1. **Close** the quote the app opened: `'`
2. **Inject** your logic: name a user, or `OR 1=1`
3. **Re-balance / comment** the remainder: `-- -` (or `#`)

---

# PART 4, Which Injection Is It? (reading the backend)

The payload language must match the interpreter. On POLE POSITION I tested several and let the results classify it:

| Payload tried | Result | Conclusion |
|---|---|---|
| `admin)(&)` (LDAP) | Login failed | not LDAP |
| `admin'-- -` (SQL) | success | **SQL** |
| `admin` + `{"$ne":1}`-style | (n/a) | would hint NoSQL/Mongo |

Tells to recognise:
- **SQL**: quote `'` breaks things; `--`/`#` comments work; error mentions SQL syntax.
- **LDAP**: parens/wildcards `)(*&|` matter; app speaks of a "directory." *(That was ROSTER HQ.)*
- **NoSQL (Mongo)**: JSON operators like `{"username":"admin","password":{"$ne":null}}` bypass; app is often Express + Mongo.

**Meta-skill:** when one injection language does nothing, switch languages rather than giving up, match it to the datastore.

---

# PART 5, Beyond Auth Bypass (a map for harder SQLi)

This box ended at login bypass, but SQLi usually goes further. Keep these for when a box wants data extraction:

- **UNION-based:** `' UNION SELECT username,password FROM users-- -`, append your own result set to read other tables. (Match column count/types first with `ORDER BY n` / `UNION SELECT NULL,NULL`.)
- **Error-based:** provoke DB errors that leak data in the message.
- **Blind boolean:** no output, but `AND 1=1` vs `AND 1=2` changes the page → extract data bit by bit.
- **Blind time-based:** `' OR SLEEP(5)-- -`, infer true/false from response delay when there's no visible difference.
- **Automation:** `sqlmap -u <url> --data="username=*&password=x"` automates detection + extraction once you've found the injectable field.

---

# PART 6, The Real Fix

The root cause is building SQL by string concatenation. The fix is **parameterised queries (prepared statements)**, the input is sent to the database *separately* from the query text, so it can never be parsed as SQL:
```python
# SAFE — placeholders; the driver binds username/password as pure data
db.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
```
No quote you type can escape a bound parameter, `admin'-- -` becomes a literal search for a user literally named `admin'-- -`, which doesn't exist. Additionally:
- **Hash passwords** (bcrypt/argon2) and compare in code, never store or match plaintext in the query.
- **Least privilege** DB account; don't leak raw SQL errors to users.
- Don't gate secrets solely on "which username the query returned."

Same shape as every injection fix: *keep untrusted data in a channel the interpreter treats strictly as data.*

---

# Glossary

- **Prepared statement / parameterised query**, sending query text and data separately (`?` placeholders) so input can't be parsed as SQL. The fix.
- **Comment (`--`, `#`)**, SQL "ignore the rest of the line"; used to delete the password check. MySQL needs `-- ` (trailing space) → `-- -`.
- **SQL injection (CWE-89)**, rewriting a SQL query via unsanitised input.
- **UNION injection**, appending `UNION SELECT ...` to read other tables.
- **Blind SQLi**, no direct output; infer data via boolean/time differences.
- **sqlmap**, automated SQLi detection/exploitation tool.
- **Auth bypass**, logging in without valid credentials by manipulating the login query.

---

# Where to Go Next

- Drill the payloads on **PortSwigger Web Security Academy → SQL injection** labs (auth bypass, UNION, blind).
- Build a tiny vulnerable Flask+SQLite login with string-concatenated SQL, bypass it with `admin'-- -`, then switch to `?` placeholders and watch it become un-bypassable.
- Learn `sqlmap` basics for when a box needs full data extraction.
- Keep the classification habit: **SQL (`'`/`--`) vs LDAP (`)(*`) vs NoSQL (`$ne`)**, read the app, pick the language.

The transferable idea: **a quote you can inject is a query you can rewrite**, and commenting the tail out (`-- -`) is more reliable than trying to satisfy the rest of the query.
