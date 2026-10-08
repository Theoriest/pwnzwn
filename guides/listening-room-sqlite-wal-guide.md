# Masterclass: SQLite WAL Forensics, Recovering a "Deleted" Value, From Zero

**Companion to:** `listening-room-sqlite-wal-writeup.md`

This is a **database-forensics** challenge: a value was written into SQLite, then overwritten, and your job is to recover the original. The guide teaches, from zero: what SQLite and its WAL are, why "deleted"/"updated" data survives, how to inspect a DB **safely** (without destroying evidence), how to carve old values from the WAL, and how to recognise/decode the `base64 → zlib` wrapping. Plus the single most important operational lesson: **don't open evidence with the live engine.**

---

## How to read this

- **Part 0**, what SQLite is, and the `.db` / `-wal` / `-shm` trio.
- **Part 1**, why "deleted" data survives (the one idea).
- **Part 2**, the cardinal rule: don't checkpoint your evidence.
- **Part 3**, inspecting safely + carving the WAL.
- **Part 4**, recognising and decoding the payload (`eJw` → base64 → zlib).
- **Part 5**, a general DB-recovery toolkit.
- **Part 6**, fixes / secure handling.
- **Glossary**.

---

# PART 0, SQLite and the WAL

**SQLite** is a serverless database that stores an entire database in a single file (`library.db`). Many apps run it in **WAL mode** (Write-Ahead Logging) for speed/concurrency. In WAL mode you'll see up to three files:

| File | Role |
|---|---|
| `library.db` | the main database (committed, checkpointed pages) |
| `library.db-wal` | the **Write-Ahead Log**, recent changes **not yet merged** into the main DB |
| `library.db-shm` | shared-memory index into the WAL (coordination) |

**How WAL works:** instead of writing changes straight into `library.db`, SQLite appends them as **frames** (page snapshots) to `-wal`. Periodically a **checkpoint** copies those frames back into the main DB and resets the WAL. Until that happens, the `-wal` file holds the newest data, *and the frames it appended can include multiple versions of the same page over time.* That history is the forensic goldmine.

---

# PART 1, The One Idea: "Deleted" ≠ Gone

> **In a database, `DELETE`/`UPDATE` usually just marks or overwrites a pointer, the old bytes linger until something reuses that space.**

On this box, the app did roughly:
```sql
INSERT INTO pressings(title,receipt) VALUES('Test pressing', '<secret receipt>');  -- "queued"
UPDATE pressings SET receipt='withdrawn' WHERE id=1;                                -- "revised"
```
The live table now says `withdrawn`. But the **WAL frames** still contain the page as it was when the secret was inserted. Recovering the secret = reading those old frames. The same principle covers **freelist pages** (deleted rows) and **slack space** in the main DB.

---

# PART 2, The Cardinal Rule: Don't Checkpoint Your Evidence

This is the mistake I want you to *not* repeat. If you run:
```bash
sqlite3 library.db "SELECT * FROM pressings;"
```
...SQLite opens the DB in WAL mode and, on close, often **checkpoints**, folding the WAL into the main file and **truncating/removing `-wal`**. You've just destroyed the history you came for. (In this challenge that turned a clean recovery into a *truncated* one, costing a re-download.)

**Rules for DB evidence:**
1. **Work on a copy.** `cp -r bundle /tmp/work` and touch only the copy.
2. **Read the WAL as raw bytes** (`strings`, `xxd`), not with the live engine.
3. If you must query, copy all three files together and set them read-only, or use a forensics-aware reader. Never let the engine write.

---

# PART 3, Inspecting Safely & Carving the WAL

### 3.1 Identify the files
```bash
file *            # confirms 'SQLite 3.x database' and 'SQLite Write-Ahead Log'
cat desk.log      # context: 'test pressing queued' / 'catalogue revised'
```
The log phrasing (*written → revised*) + the presence of a `-wal` = "recover the pre-revision value."

### 3.2 See the schema without destroying anything
Reading just the schema from a **copy** is low-risk, but the safest "what columns exist" is to `strings` the main DB:
```bash
strings library.db | grep -i 'CREATE TABLE'
# CREATE TABLE pressings(id INTEGER PRIMARY KEY, title TEXT, receipt TEXT)
```

### 3.3 Carve old values from the WAL (the key step)
The WAL holds page snapshots as readable-ish bytes. Pull candidate values straight out:
```bash
strings -n 6 library.db-wal | grep -E 'Test pressing|withdrawn|eJw|safctf'
```
You'll see the record's **versions** in order, the original secret, (sometimes) partial copies, and the revision (`withdrawn`). The original is the one you want.

> If values look binary, `xxd library.db-wal | less` and search for the table/row markers, or use a WAL parser. But `strings` cracks most CTF versions.

---

# PART 4, Recognising & Decoding the Payload

The recovered receipt was `eJwrTkxLLkmrNjRKSko2NUzRNTcxNdA1MUk2001MM07TNTQ3MjY1NEmySExMqQUALKEM0A==`. Two signatures to memorise:

- **`eJw` (or `eJx`/`eJz`) at the start of a base64 string ⇒ zlib-compressed data.** Base64 of the zlib magic `78 9c` is `eJw…`. (`H4sI` ⇒ gzip; `UEsDB` ⇒ a ZIP; `iVBOR` ⇒ PNG, build this cheat-sheet.)
- A trailing `==` ⇒ base64 padding.

Decode:
```python
import base64, zlib
s = "eJwrTkxLLkmrNjRKSko2NUzRNTcxNdA1MUk2001MM07TNTQ3MjY1NEmySExMqQUALKEM0A=="
print(zlib.decompress(base64.b64decode(s)).decode())
# safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}
```
**Truncation tip:** if `zlib.decompress` raises *"incomplete or truncated stream,"* your input is cut off (as mine was after the bad checkpoint). Use `zlib.decompressobj().decompress(raw)` to get **partial** plaintext, enough to confirm you're on the right track, then go fetch the complete bytes.

The decoded value is a `safctf{UUID}`, the **collection receipt**, which you submit to the desk:
```bash
curl -s -X POST http://TARGET/submit -H 'Content-Type: application/json' \
  --data '{"answer":"safctf{...}"}'      # returns the real flag
```

---

# PART 5, A General DB-Recovery Toolkit

When a value was "removed" from a DB, check, in order:
1. **The WAL** (`-wal`), most recent pre-commit history (this box).
2. **Freelist / unallocated pages**, deleted rows linger until reused. Tools: `sqlite3 … 'PRAGMA freelist_count'` *(on a copy!)*, or carve with `strings`/`xxd`.
3. **Rollback journal** (`-journal`), the non-WAL equivalent; holds pre-change page images.
4. **`.backup` / VACUUM artifacts**, and OS-level slack.
5. **Dedicated tools:** `sqlite3_analyzer`, `undark`, `walitean`, or a hex editor for manual B-tree cell carving.

For other engines: MySQL binlogs, Postgres WAL/`pg_waldump`, and redo logs serve the same role.

---

# PART 6, Fixes / Secure Handling

- **If you're the developer:** don't "hide" secrets with an `UPDATE` and assume they're gone, the WAL/freelist retains them. To truly remove: `VACUUM` (rewrites the DB, dropping freed data), `PRAGMA secure_delete=ON` (zeroes deleted content), and checkpoint+delete the WAL. Better: never store the secret in a reachable artifact.
- **If you're the investigator:** preserve originals (hash them, work on copies), and read journals/WAL offline. Opening with the live engine mutates evidence.

---

# Glossary

- **SQLite**, a serverless, single-file relational database.
- **WAL (Write-Ahead Log, `-wal`)**, appended page snapshots of recent changes not yet merged into the main DB; holds recoverable history.
- **`-shm`**, shared-memory index coordinating WAL access.
- **Checkpoint**, merging WAL frames into the main DB and resetting the WAL; **destroys** the standalone history.
- **Frame / page**, the unit of data SQLite stores; the WAL records versions of pages.
- **Freelist**, pages freed by deletes, reusable later; old row bytes persist until reused.
- **Rollback journal (`-journal`)**, the non-WAL crash-recovery file; also holds pre-change images.
- **`eJw…`**, base64 of the zlib magic `78 9c`; signals zlib-compressed data.
- **VACUUM / `secure_delete`**, SQLite mechanisms that actually scrub freed data.

---

# Where to Go Next

- Build a toy: create a SQLite DB in WAL mode, `INSERT` a secret, `UPDATE` it away, then recover it from `-wal` with `strings`, and watch it vanish after you `VACUUM` or checkpoint.
- Learn the file-signature cheat-sheet for base64 blobs (`eJw`=zlib, `H4sI`=gzip, `UEsDB`=zip, `iVBOR`=png, `/9j/`=jpeg).
- Practise non-destructive handling: always `cp` first, hash originals, read journals as bytes.
- Explore `undark`/`walitean` and `pg_waldump` for deeper recovery.

The transferable idea: **databases keep history you didn't ask them to keep**, in WAL frames, journals, and freed pages. Recover it by reading those artifacts **raw**, and never let the live engine touch your evidence.
