# A Complete Beginner's Guide to the SIDE QUEST LFI Challenge

**Companion to:** `sidequest-page-lfi-writeup.md`

The writeup tells the story of *what I did* (detours and all). This guide explains *why each step works*, starting from zero. I'm assuming terms like "Flask", "route", "parameter", "LFI", "path traversal", and "/proc" are fuzzy. By the end you should understand how to find a hidden input, turn it into reading arbitrary files, and pull a secret out of a running process, and *why* each of those is possible.

This box has no shells to pop, it's a **"read a file you shouldn't be able to"** challenge. That makes it a great lesson in two things most beginners skip: **fuzzing parameters (not just paths)** and **what you can do once you can read files**.

---

## How to read this guide

- **Part 0**, background: clients/servers, what Flask is, routes vs. parameters, and the one image-format detour.
- **Part 1**, the one idea behind this whole challenge.
- **Part 2**, finding the hidden input (parameter fuzzing).
- **Part 3**, what LFI and path traversal actually are.
- **Part 4**, turning file-read into the flag (`/proc`).
- **Part 5**, two sidebars you asked about: **where a "console" runs**, and **the image decoy**.
- **Part 6**, how to fix it all.
- **Glossary** at the end. If a word confuses you, jump there.

---

# PART 0, The Background You Actually Need

## 0.1 Client, server, and why this one is "dynamic"

As always: your browser/`curl` is the **client** (sends requests); a program on the far machine is the **server** (sends responses). But there's a crucial split in *what kind* of server you're facing:

- A **static** server (like Apache serving files) just hands back files that already exist on disk.
- A **dynamic** server runs a **program** that *builds* each response on the fly.

How do you tell? The `Server:` header. Here it said **`Werkzeug/3.1.9 Python/3.10.21`**. Werkzeug is the little web server that **Flask** (a Python web framework) uses. So this is a **Python program** deciding what to do with every request, which means the bug will be in *that program's logic*, not in some file sitting in a web folder.

## 0.2 What Flask is, in one breath

**Flask** is a popular Python toolkit for writing web apps. The core idea you need: the programmer declares **routes**, specific URLs the app knows how to answer, like this:

```python
@app.route("/health")
def health():
    return "OK"

@app.route("/")
def home():
    page = request.args.get("page")   # reads ?page=... from the URL
    ...
```

Everything the app can do lives behind a route the programmer wrote. There is no route for `/admin` unless they wrote one. That's why "guessing routes" (Part 0.4) is a core move, you're trying to discover which URLs the programmer actually created.

## 0.3 Utility routes (why `/health` is a *hint*)

A **utility route** is a small endpoint that exists for *operations*, not for people. The classic is **`/health`** (also `/healthz`, `/ping`, `/status`): uptime monitors and load balancers hit it constantly just to check "is the app alive?", and it replies something tiny like `OK`.

Why does spotting one matter to an attacker? Because it tells you the app's **shape**: this is a **hand-written set of named endpoints**, not a file browser. So when `/health` itself does nothing exciting, the lesson isn't "dead end", it's *"this app takes specific, named inputs; go find the ones that aren't advertised."* On this box, the un-advertised input wasn't another route at all, it was a **query parameter** (next section).

## 0.4 Routes vs. parameters, the distinction that cracked this box

A URL can carry input in more than one place. Two matter here:

- **The path**, `/health`, `/about`, `/user/42`. These are **routes**. Fuzzing paths means trying `/FUZZ` with a wordlist.
- **Query parameters**, the part after `?`: `/?page=about` has a parameter named `page` with value `about`. The app reads these with `request.args.get("page")`.

Here's the trap this challenge sets: you can scan for **routes** forever (`/`, `/health`, `/admin`...) and find nothing, because the real input is a **parameter** on a route you *already know*. The homepage `/` quietly accepts `?page=...` and never tells you. **Finding hidden parameters is a different skill from finding hidden paths**, and it's the whole key here (Part 2).

## 0.5 The image detour (AVIF, binwalk, and a famous red herring)

With no form to type into, the natural first instinct is "the secret's hidden in the image." Worth checking, here's how, and why it was a dead end:

- **AVIF** is just a modern **image format** (based on the AV1 video codec) that compresses images small for fast web loading. Nothing magic.
- **`binwalk`** is a tool that scans a file for *other files/data embedded inside it* (a common way to hide things in CTFs, e.g. a zip glued onto a JPEG).
- Running it here found only: `Copyright (c) 1998 Hewlett-Packard Company`. That looks spooky but is **boilerplate**: it's the copyright tag inside the **standard sRGB colour profile** (ICC profile) that's embedded in a huge share of all images. HP and Microsoft co-authored sRGB in 1996-98, so that string rides along inside countless pictures.

**Lesson:** checking the image was *correct practice*; concluding "this HP string is noise, move on" was the *correct read*. Knowing which binwalk hits are boring boilerplate saves you hours.

---

# PART 1, The One Idea Behind This Challenge

Every file-read bug is the same sentence:

> **The program let my input decide *which file it opens*, and trusted that input not to be malicious.**

If you can influence a filename the server opens, and the server doesn't carefully restrict it, you can walk its filesystem. Everything below, finding the parameter, the `../` traversal, reading `/proc`, is just *executing* that one idea. Hold it.

---

# PART 2, Finding the Hidden Input (Parameter Fuzzing)

## 2.1 Why route-fuzzing failed

Scanning `/FUZZ` with wordlists only ever returned `/` and `/health`, because **the input wasn't a route.** This is the moment many beginners get stuck, they conclude "there's no attack surface." There is; it's just in a different *part* of the URL.

## 2.2 The technique: fuzz parameter *names*

A **parameter** is invisible until you guess its name. So we brute-force **names**, watching for one that changes the app's behaviour. The tool is still `ffuf`, but the `FUZZ` keyword goes in the **query string**:

```bash
ffuf -u 'http://54.72.82.22:8030/?FUZZ=test' \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc all -fs 8429
```

Reading it:
- `-u '...?FUZZ=test'`, `ffuf` replaces `FUZZ` with each candidate **parameter name** and sends `?name=test`.
- `-w burp-parameter-names.txt`, a wordlist of **real-world parameter names** (this one is derived from names Burp Suite has seen across many apps, `id`, `file`, `page`, `url`, `debug`, ...).
- `-fs 8429`, **filter out** responses that are 8429 bytes (the normal homepage size). A parameter that does nothing returns the normal page; one that *does* something changes the size, so it slips past the filter and shows up.

Out came **`page`**. That single word is the entire pivot of the box: the homepage accepts `?page=`, and nothing on the site ever mentioned it.

**Takeaway:** when routes dry up, **fuzz parameter names**. Hidden inputs are where minimal apps keep their bugs.

---

# PART 3, LFI and Path Traversal

## 3.1 What `page` was doing

Probing it:
```bash
$ curl -s 'http://.../?page=test' | tail -1
<h2>Oops! Something went wrong while loading the page.</h2>
```
"loading the page" is the tell: the app takes your `page` value and tries to **open a file by that name**, something like:
```python
page = request.args.get("page")
return open("pages/" + page).read()     # <-- the bug
```
So `?page=about` reads `pages/about`. The app *trusts* that you'll only ask for real page names. We won't.

## 3.2 Path traversal: the `../` trick

On every filesystem, `..` means **"go up one directory."** From `/app/pages/`, the path `../` lands in `/app/`, `../../` in `/`, and so on. So if the app opens `"pages/" + page`, we set:
```
page = ../../../../etc/passwd
```
and the file it actually opens becomes:
```
pages/../../../../etc/passwd   →   /etc/passwd
```
The `../`s "climb out" of the intended `pages/` folder, up to the filesystem root `/`, then back down into `/etc/passwd`. We add a few extra `../` for safety, once you're at `/`, more `../` do nothing, so over-supplying is harmless.

```bash
$ curl -s 'http://.../?page=../../../../etc/passwd' | grep root:
root:x:0:0:root:/root:/bin/bash
```
`/etc/passwd` is the classic proof file: world-readable, always present, unmistakable. Seeing it = **LFI confirmed** (Local File Inclusion via path traversal).

## 3.3 Why it's called "Local File Inclusion"

*Local* = a file already on the server (not one you upload). *File Inclusion* = the app **includes/returns the file's contents** based on your input. The umbrella weakness is **Path Traversal (CWE-22)**: input that escapes an intended directory. You'll read the two terms used almost interchangeably for this exact bug.

---

# PART 4, Turning File-Read Into the Flag (`/proc`)

Reading `/etc/passwd` proves the bug but isn't the prize. Now: *which file holds the secret?* On Linux, the fastest answers live in **`/proc`**, a **virtual filesystem** the kernel generates on the fly, describing every running process. `/proc/self/` always points at *the process reading it*, here, the Flask app itself. The greatest hits:

| File | What it gives you |
|---|---|
| `/proc/self/environ` | the process's **environment variables**, tokens, config, and (here) the flag |
| `/proc/self/cmdline` | the exact command that launched it (told us `python app/app.py`, so the code is at `/app/app.py`) |
| `/proc/self/cwd/...` | a symlink to the process's working directory, handy to grab the app's own source |

These files are **NUL-separated** (fields split by a zero byte, not newlines), so we translate those to newlines to read them:
```bash
$ curl -s 'http://.../?page=../../../../../../proc/self/environ' | tr '\0' '\n' | grep -i flag
FLAG=safctf{9fdb535dbf8020d488bf8d6a51287778}
```
`tr '\0' '\n'` = "replace NUL bytes with newlines." And there's the flag, it was an **environment variable** all along.

**Why the flag was reachable at all:** it was stored in the environment, and an LFI reads the environment for free. (That's a design mistake; see Part 6.)

**General LFI target list for next time:** `/etc/passwd` (proof), `/proc/self/environ` (secrets), `/proc/self/cmdline` (where the code is), then the app source (`app.py`) to read its logic and find more bugs, and config files (`.env`, `settings.py`, `config.php`).

---

# PART 5, Two Sidebars You Asked For

## 5.1 Where does a "console" actually run? (the JS-injection question)

A natural thought when you're stuck: *"I can run JavaScript in the browser console, can I inject code to attack the server?"* The key realisation:

- The **browser DevTools console runs JavaScript on *your own computer*, inside your browser.** It can read the page, call the page's own JS, and send requests to the server, but it **never executes code on the server**. So "console JS" only matters for **client-side** bugs (XSS, secrets sitting in page JavaScript, client-side login checks). On a server-side box like this, it can't be the way in.
- The thing you were *really* imagining, a console that runs code **on the server**, does exist in Flask: the **Werkzeug debugger** at `/console`, an interactive prompt that executes **Python on the server**. That's genuine RCE... but it only appears when the app runs in **debug mode**. This box had debug **off** (`/console` → 404, plain error pages), so it wasn't available.

**The mental model to keep:** *a console gives you code execution on the machine it runs on.* Browser console → your machine. Werkzeug debugger → the server. Always ask "whose CPU is this running on?" before treating a console as an exploit.

## 5.2 The image decoy (and reading binwalk sanely)

Checking the image was the right reflex, hiding data in images (steganography) is common. The skill is **recognising boilerplate**. The `Copyright (c) 1998 Hewlett-Packard Company` string isn't a message; it's part of the **standard sRGB colour profile** baked into countless images. When binwalk / `strings` / `exiftool` surface well-known profile or format metadata, that's usually noise. Real hidden data looks like *appended archives*, *unexpected file signatures mid-file*, or *high-entropy blobs*, not a colour-profile copyright.

---

# PART 6, How to Fix It All

## 6.1 Fix the LFI (the one real bug)

The root cause is letting input choose a filename. Two solid fixes:

```python
# BAD — input becomes part of a path
return open("pages/" + request.args.get("page")).read()

# GOOD (allow-list) — input only *selects* from known-safe files
PAGES = {"home": "home.html", "about": "about.html"}
name = request.args.get("page", "home")
if name not in PAGES:
    abort(404)
return render_template(PAGES[name])
```
If you *must* build a path, **canonicalise and verify it stays inside the intended directory**:
```python
import os
base = "/app/pages"
full = os.path.realpath(os.path.join(base, name))
if not full.startswith(base + os.sep):
    abort(403)         # someone tried to climb out with ../
```
Same shape as every injection fix: *keep untrusted data in a channel that's treated strictly as data*, here, an index into an allow-list, never raw path text.

## 6.2 Don't keep high-value secrets in the environment

The flag was readable because it was an env var and the LFI reads `/proc/self/environ`. For real systems, keep secrets in a dedicated secrets manager, and assume any file-read/RCE bug exposes the whole environment instantly.

## 6.3 Defence in depth

- Don't run the **Werkzeug dev server** in production (it's for development).
- Run the app as a **low-privileged user** in a minimal container, so even a working LFI reads as little as possible.

---

# Glossary

- **AVIF**, a modern image format (AV1-based) for strong web compression. Just a picture; not inherently suspicious.
- **binwalk**, a tool that scans a file for other files/data embedded inside it.
- **Client / Server**, the thing sending the request vs. the program answering it.
- **ffuf**, a fast fuzzer; swaps a `FUZZ` keyword for each wordlist entry. Fuzz **paths** (`/FUZZ`) or **parameter names** (`/?FUZZ=test`).
- **Flask**, a Python web framework; apps are built from **routes**.
- **ICC / sRGB colour profile**, standard colour metadata embedded in many images; its HP/1998 copyright string is boilerplate, not a clue.
- **LFI (Local File Inclusion)**, making an app read/return a server-side file of your choosing via unsanitised input.
- **Parameter (query parameter)**, input in the URL after `?`, as `name=value`; read in Flask with `request.args.get("name")`.
- **Path traversal**, using `../` to escape an intended directory and reach other files (CWE-22).
- **/proc**, a Linux virtual filesystem describing running processes; `/proc/self/` is the current process. `environ` = env vars, `cmdline` = launch command.
- **Route**, a specific URL a web app is programmed to handle (e.g. `@app.route("/health")`).
- **Utility route**, a small ops endpoint (e.g. `/health`) not meant for users; a hint about the app's shape.
- **Werkzeug**, the development web server Flask runs on; its **debugger** (`/console`, debug mode only) executes Python on the server.

---

# Where to Practise Next

- **Re-solve from the headers:** notice `Werkzeug` → "dynamic Python app" → when routes dry up, **fuzz parameters** → test any file-loading input for `../`.
- **Drill parameter fuzzing:** learn `ffuf -u '...?FUZZ=test' -fs <baseline>` cold. It finds inputs scanners miss.
- **Build your LFI target list:** `/etc/passwd`, `/proc/self/{environ,cmdline}`, the app's own source, `.env`/config. Reading source turns one LFI into finding the *next* bug.
- **Look up:** OWASP "Path Traversal" and "File Inclusion", PayloadsAllTheThings (File Inclusion section), and Flask's docs on `send_file`/`render_template` to see the safe ways to do what this app did unsafely.

The goal isn't to memorise this one LFI. It's the pattern underneath: **find the input the app forgot to tell you about, then stop trusting it**, most web boxes are a new costume on that.
