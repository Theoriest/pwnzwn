# Masterclass: Exposed Backups, Source & Secrets, Content Discovery / Forced Browsing, From Zero

The bug behind COMEBACK KIT, and one of the most reliable findings in real-world testing. You'll learn why artifacts leak into the web root, the full list of what to hunt for, how to do content discovery properly (wordlists, extensions, recursion), how to triage what you find, and how to stop leaking.

## How to read this

- **PART 0**, the mental model: the web root is a public folder.
- **PART 1**, the one idea.
- **PART 2**, the hit-list of files to hunt.
- **PART 3**, doing content discovery right.
- **PART 4**, triage: turning a file into an exploit.
- **PART 5**, finding it in the wild / severity.
- **PART 6**, the fixes.
- Glossary + next.

---

# PART 0, The Building Blocks

A web server maps URLs to files under a **document root** (e.g. `/var/www/html`). Anything in that folder with a readable path is downloadable by anyone who knows (or guesses) the name, whether or not a page *links* to it.

"Not linked" is not "not reachable." There's no login on a static file; obscurity is the only thing hiding it, and names are guessable. This class is called **forced browsing** or **content/file discovery**: requesting paths the site never advertised.

---

# PART 1, The One Idea

> **Development and deployment constantly drop extra files into the web root, backups, archives, source, configs, VCS folders, editor leftovers. Each can be fetched directly, and each may contain source or secrets.** Enumerate predictable names; read what you get.

COMEBACK KIT literally linked its own `/backup.zip`, but even if it hadn't, a discovery scan guessing `backup.zip` would have found it.

---

# PART 2, The Hit-List

What to request, by category:

**Archives / backups**
```
backup.zip  backup.tar.gz  site.zip  www.tar.gz  app.zip  release.zip
db.sql  dump.sql  database.sql  <appname>.zip  2024.zip  old.zip
index.php.bak  config.php~  .index.html.swp  app.py.save
```
**Version control (gold mine, full source + history)**
```
/.git/HEAD  /.git/config  /.gitignore  /.svn/entries  /.hg/  /.bzr/
```
`/.git/` exposed → dump the whole repo with `git-dumper`; history often holds removed secrets.

**Configs / secrets**
```
.env  .env.example  config.json  settings.py  web.config  appsettings.json
wp-config.php  docker-compose.yml  .aws/credentials  id_rsa  *.pem  *.key
```
**Build / project artifacts**
```
package.json  composer.lock  yarn.lock  Dockerfile  Makefile
local.properties  gradle.properties  *.apk  *.jar  sourcemaps (*.js.map)
```
**Server/info**
```
robots.txt  sitemap.xml  .htaccess  .DS_Store  crossdomain.xml
phpinfo.php  server-status  /actuator/ (Spring)  /debug  /console
```
**Editor/OS leftovers**
```
file~  .file.swp  .file.swo  #file#  .orig  .tmp  Thumbs.db  .DS_Store
```

`.DS_Store` and `.git` are especially valuable: they *reveal other filenames* to then fetch.

---

# PART 3, Doing Content Discovery Right

## 3.1 Tools

`ffuf`, `feroxbuster`, `gobuster`, `dirsearch`, all do the same core job: request `BASE/WORD` for every word in a list and report interesting status codes.

```bash
ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
     -mc 200,204,301,302,307,401,403 -e .zip,.tar.gz,.bak,.sql,.old,.txt,.json -t 50
```

- `-e` appends **extensions** to each word (so `backup` → `backup.zip`, `backup.sql`, ...). This is what catches archive leaks.
- Match (`-mc`) interesting codes; **403** often means "exists but listing denied" (as `/uploads/` did on OFF THE WALL), still a signal.
- Filter noise with `-fs <size>` / `-fw <words>` / `-fc 404` after you see the baseline.

## 3.2 Wordlists that matter

- `SecLists/Discovery/Web-Content/` → `common.txt`, `raft-*-files.txt`, `raft-*-directories.txt`.
- Backup-specific: `SecLists/.../backup-files.txt`.
- Tech-specific lists (apache, nginx, php, tomcat) once you fingerprint the server.

## 3.3 Recursion & extensions

- Recurse into discovered directories (`feroxbuster` does this by default; `ffuf` with a second pass).
- Re-run with the **right extension set** for the stack (`.php` on Apache/PHP, `.aspx` on IIS, `.jsp` on Tomcat).
- Try **appending** known patterns to *existing* files: found `index.php`? request `index.php.bak`, `index.php~`, `.index.php.swp`.

## 3.4 Don't forget the obvious

Read the page's own HTML/JS first (COMEBACK KIT advertised the file). Check `robots.txt` and `sitemap.xml`, they frequently *name* the paths someone wanted hidden.

---

# PART 4, Triage: From File to Flag

Once you pull something, mine it systematically:

```bash
unzip -o loot.zip -d loot; cd loot
grep -rinE 'safctf\{|password|passwd|secret|api[_-]?key|token|BEGIN .*PRIVATE KEY' .
grep -rinE 'postgres://|mysql://|mongodb://|redis://|amqp://' .   # connection strings
find . -name '*.env' -o -name '*.pem' -o -name '*.key' -o -name 'id_*'
```

- **Source** → read auth logic, hardcoded creds, hidden endpoints, crypto keys (VELVET ROOM's AES key was in client JS; DAILY SCOOP's DB DSN was in a `secrets` zip).
- **`.git`** → `git log -p` for secrets removed in later commits.
- **Configs** → DB credentials, cloud keys, service tokens → pivot.
- **Binaries/APKs** → decompile (`jadx`, `apktool`) and grep.

For COMEBACK KIT the flag was a plain Android string resource; one `grep -r` found it.

---

# PART 5, In the Wild & Severity

- Extremely common in real assessments; often the **highest-impact, lowest-effort** finding (exposed `.git` or `.env` can mean full source + prod credentials).
- Severity scales with contents: a marketing `backup.zip` is low; a `.env` with prod DB + cloud keys is critical.
- Automated scanners and opportunistic bots hammer these names constantly, so a leak is usually found fast by someone.

---

# PART 6, The Fixes

1. **Keep non-web files out of the document root.** Build/deploy to a path the server never serves; copy only the intended static assets in.
2. **Server-level denies** for risky patterns:
   ```apache
   # Apache
   <FilesMatch "(\.(bak|old|sql|zip|tar|gz|tgz|env|pem|key|swp|orig)|~|#)$">
     Require all denied
   </FilesMatch>
   RedirectMatch 404 /\.git
   ```
   ```nginx
   # nginx
   location ~ /\.(git|svn|env|ht) { deny all; }
   location ~ \.(bak|old|sql|zip|tar|gz|env|pem|key|swp|orig)$ { deny all; }
   ```
3. **Disable directory listing** (`Options -Indexes`).
4. **No secrets in client artifacts** (JS bundles, sourcemaps, APKs, mobile binaries), they're public by definition. Strip sourcemaps from prod.
5. **CI check**: fail the build if `.git`, `.env`, `*.bak`, archives, or keys land in the deploy artifact.
6. **Monitor** access logs for forced-browsing of these names and alert.

---

# Glossary

- **Document root / web root**, the directory the server exposes; everything in it is fetchable by path.
- **Forced browsing / content discovery**, requesting unlinked paths to find hidden files/dirs.
- **Backup leak**, archive/`.bak`/`~`/`.sql` left where it's served.
- **VCS exposure**, a readable `.git`/`.svn` folder → full source & history.
- **Sourcemap**, `*.js.map`; reconstructs original (often commented) source from minified JS.
- **403 vs 404**, "forbidden" often means *exists*; "not found" means *absent*. 403 is a lead.

# Where to Go Next

- Run `ffuf` with `-e .zip,.bak,.sql,.env` against a lab target; practice triaging a `.git` dump with `git-dumper`.
- Related in this dojo: **afterhours** (robots.txt + forced browsing a listing-disabled dir) and **velvetroom**/**dailyscoop** (secrets found in client JS / leaked config), same theme: *the app handed you more than it meant to.*
