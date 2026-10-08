# Masterclass: Path-Normalization Scope Bypass (TOCTOU), Harbor Lights, From Zero

**Companion to:** `harborlights-path-bypass-writeup.md`

This box is a precise, important bug: an app checks permission on a **path string** and then lets a storage layer **rewrite that path** before using it. The two disagree, and you slip out of the allowed area. The guide teaches, from zero: what path normalization is, why "check then normalize" is exploitable (TOCTOU), the full toolkit of traversal encodings (and which *don't* work and why), how to read the response oracle, and how to fix it. It generalises to proxies, static-file servers, S3-style object stores, archive extractors (zip-slip), and SSRF allow-lists.

---

## How to read this

- **Part 0**, paths, prefixes, and normalization.
- **Part 1**, the one idea: authorize the resolved path, not the raw string.
- **Part 2**, recon: finding the private key (the side-channel file).
- **Part 3**, the traversal toolkit (encodings that work, and the ones that don't, with *why*).
- **Part 4**, reading the oracle (flag vs. "decoy" vs. blocked).
- **Part 5**, fixes.
- **Glossary**.

---

# PART 0, Paths, Prefixes, and Normalization

A storage key like `public/lineup.txt` is a **path**: segments separated by `/`. Two operations matter:

- **Prefix check**, "is this key allowed?" Often `key.startswith("public/")`. Pure string comparison.
- **Normalization**, resolving `.` (here) and `..` (parent) into a **canonical** path. `public/../finance/final.txt` *normalizes* to `finance/final.txt`. Filesystems, URL routers, and object-store adapters do this automatically.

The danger is doing these **in the wrong order**: checking the *raw* string, then normalizing before the real lookup.

---

# PART 1, The One Idea

> **Authorize the path you will actually use (the normalized one), not the string the attacker handed you.**

When an app checks `startswith("public/")` on the raw key but the storage adapter later collapses `..`, the key `public/../finance/final.txt`:
- **passes** the check (it literally starts with `public/`), and
- **resolves** to `finance/final.txt` (outside `public/`).

This is a **TOCTOU** (time-of-check vs. time-of-use) bug, the value's *meaning* changes between the check and the use. On Harbor Lights that's exactly the gap between the scope check and the `edge-store` adapter.

---

# PART 2, Recon: Find the Private Key

Two endpoints, plus a side file:
```bash
curl -s TARGET/api/objects              # lists only public/* keys
curl -s TARGET/downloads/storage.json   # LEAKS the full inventory + scope + adapter
```
`storage.json` is the gift: it lists `finance/final.txt` (not in the public listing) and tells you `scope: "public/*"`. **Always pull the manifest/config/side file**, it names the thing you're trying to reach. Without the exact private key, a traversal has nowhere to go.

Confirm the retrieve endpoint *also* enforces scope (so it's not a trivial IDOR):
```bash
curl -s 'TARGET/api/object?key=finance/final.txt'   # blocked → there IS a check to bypass
```

---

# PART 3, The Traversal Toolkit (and what fails)

Goal: a key that **starts with `public/`** (to pass the check) but **normalizes to `finance/final.txt`** (to escape). The canonical payload:
```
public/../finance/final.txt
```

### 3.1 Encodings that are equivalent (all worked here)
The server URL-decodes **before** normalizing, so every encoding of `../` collapses the same way:
| Form | Why it works |
|---|---|
| `public/../finance/final.txt` | literal |
| `public/..%2ffinance%2ffinal.txt` | `%2f` = `/` |
| `public%2f..%2ffinance%2ffinal.txt` | whole path encoded |
| `public%2F..%2Ffinance%2Ffinal.txt` | hex case doesn't matter |
| `public/%2e%2e/finance/final.txt` | `%2e` = `.` |
| `public/./../finance/final.txt` | `.` is a no-op segment |
| `public/..//finance/final.txt` | empty segment collapses |

**Rule of thumb:** if decode-then-normalize is in play, try literal, `%2e`(`.`), `%2f`(`/`), double-encoding (`%252e`), and mixed case, they're usually interchangeable.

### 3.2 Things that *don't* work (know why)
| Payload | Why it fails |
|---|---|
| `finance/final.txt` | no `public/` prefix → fails the check before traversal matters |
| `public/\../finance/final.txt`, `...%5c...` | **backslash is not a POSIX separator**, on Linux `\` is a literal char, so no parent step; stays inside `public/` |
| `public/../../finance/final.txt` | **over-traversal**, two `..` from `public/` overshoot the base; the normalizer clamps (can't go above root), landing somewhere other than `finance/` |
| `public/....//...` | `....//` only collapses to a parent on *some* normalizers (the dot-dot-slash-slash trick); not this one |

**Lessons:** match the server's OS (`/` vs `\`), and use **exactly enough** `..` to reach the sibling directory, one level here (`public/` → base → `finance/`). If you overshoot, compensate with a decoy segment: `public/a/../../finance/...` (go *into* `a`, then up twice).

### 3.3 Other bypass families (for when `..` is filtered)
- **Double URL-encoding:** `%252e%252e%252f` (decoded twice by layered proxies).
- **Unicode/overlong** `..` (`%c0%ae`) on tolerant decoders.
- **Absolute paths / scheme tricks** for SSRF allow-lists (`http://allowed@evil`, `http://evil#allowed`).
- **Parameter pollution:** `?key=public/x&key=finance/y`, if the auth code reads the first value and the store reads the last (or vice-versa). (Tried here; the app was consistent, so it didn't split, but it's always worth a shot.)

---

# PART 4, Reading the Oracle

Three distinct responses tell you *where your path landed*:
| Response | Meaning |
|---|---|
| `{"body":"safctf{...}"}` | ✅ escaped to `finance/final.txt` |
| `{"body":"The next performance begins at eight."}` | 🟡 resolved **back inside** `public/` (that's `lineup.txt`), your traversal was neutralized or overshot |
| `{"message":"The request could not be completed."}` | ⛔ failed the `public/` prefix check (no valid prefix) |

The **🟡 "public decoy"** is the useful signal: it means the check passed but normalization kept you *inside* scope, so adjust the **depth/encoding** of your traversal rather than abandoning the technique. Treating a non-flag 200 as "wrong" (instead of "almost") is how people miss these.

---

# PART 5, The Fixes

**Canonicalize first, then authorize**, the golden rule:
```python
import posixpath
BASE = "public/"
raw = request.args["key"]
# resolve against the base, collapse . and ..
resolved = posixpath.normpath(posixpath.join(BASE, raw)) if not raw.startswith(BASE) else posixpath.normpath(raw)
if not (resolved == BASE.rstrip("/") or resolved.startswith(BASE)):
    abort(403)                      # authorize the RESOLVED path
return store.get(resolved)
```
Also:
- **Reject `..` outright** (after URL-decoding) rather than trying to sanitize it away.
- Prefer an **allow-list**: map known public keys → storage locations; never accept free-form paths.
- **Don't disclose private keys** in a world-readable manifest (`storage.json`).
- Decode **once**, in one place, so "decode vs. normalize vs. check" ordering is unambiguous.

---

# Glossary

- **Path normalization / canonicalization**, resolving `.`/`..`/duplicate separators into a single canonical path.
- **Prefix / scope check**, authorizing a key by string match (`startswith("public/")`).
- **TOCTOU (CWE-367)**, time-of-check/time-of-use: the value's meaning changes between validation and use.
- **Path traversal (CWE-22)**, using `..` to escape an intended directory.
- **Broken access control (CWE-863/285)**, authorization that can be bypassed; here, by normalization.
- **Zip-slip / SSRF allow-list bypass**, the same "check the string, resolve differently" bug in archive extraction / URL filtering.
- **Oracle**, a response that reveals where your input landed (flag vs. public decoy vs. blocked).

---

# Where to Go Next

- Drill **PortSwigger → Path traversal** labs (encoding, double-encoding, null-byte, validate-start-of-path bypasses).
- Study **zip-slip** and **SSRF allow-list bypass**, same root cause, different sink.
- Build a tiny Flask store that does `startswith("public/")` then `open(key)`, exploit it, then fix it with `normpath`-then-authorize and watch every payload die.
- Internalise the oracle habit: a 200 that isn't the flag is often *"you're inside scope, traverse more/differently,"* not *"this doesn't work."*

The transferable idea: **a permission check is only as good as the value it checks.** If the string you authorize isn't the path you ultimately use, an attacker lives in the gap, so canonicalize first, then decide.
