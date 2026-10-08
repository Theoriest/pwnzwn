# A Complete Beginner's Guide to the AFTERHOURS QR Recovery Challenge

**Companion to:** `afterhours-qr-recovery-writeup.md`

The writeup tells the story of *what I did*. This guide explains *why each step works*, starting from zero. I'm assuming you've never solved a web/OSINT challenge before and that terms like "QR", "ROT13", "robots.txt", "403", or "forced browsing" are fuzzy. By the end you should be able to look at this box, or one like it, and understand how to **read the clues**, **follow the trail**, and **recognise the traps**, and *why* each weakness is a weakness at all.

This box has no shells and no exploits, it's a pure **treasure hunt**. That makes it a perfect first challenge: every step is "notice a clue, decode it, follow it." Take it slowly; each part builds on the one before.

---

## How to read this guide

- **Part 0** teaches the background a complete beginner needs (clients/servers, URLs, QR codes, hashing vs encryption).
- **Part 1** is the one big idea behind this whole genre of challenge.
- **Parts 2-6** walk the trail in order: the image → the cipher → the 403 → robots.txt → the flag.
- **Part 7** is the decoys and the meta-lessons.
- **The Glossary** at the end defines every term in plain English. If a word confuses you, jump there.

---

# PART 0, The Background You Actually Need

## 0.1 Client and server, in one picture

When you open a website, two computers talk:

- **The client**, your browser, or a tool like `curl`. It *sends a request*.
- **The server**, a program on another machine. It *receives the request and sends back a response*.

Think of ordering at a counter: you (client) hand over a slip (the request); the kitchen (server) reads it and hands back a plate (the response). You only control what's on your slip, in web terms, the **URL** you ask for and a few details with it.

**The single most important idea for this challenge:** *a web server will happily hand you any file you ask for by name, unless something is specifically set up to stop it.* Our whole job is to figure out the right name to ask for.

## 0.2 A URL, broken into parts

Take `http://54.72.82.22:8010/IKnewYouWouldFindThis/flag.txt`:

| Piece | Meaning |
|---|---|
| `http://` | the protocol (plain web traffic) |
| `54.72.82.22` | the server's address (here, an AWS EC2 machine) |
| `:8010` | the **port**, which "door" on the server (normal web is 80; this box uses 8010) |
| `/IKnewYouWouldFindThis/` | a **directory** (folder) on the server |
| `flag.txt` | a **file** inside that directory |

Asking for a URL is just saying "please give me the thing at this path." The server replies with the file, or with an error if it won't.

## 0.3 Status codes, the server's one-word mood

Every response comes with a number:

- **`200 OK`**, "here's what you asked for." (success)
- **`403 Forbidden`**, "I know what you're asking for, but I won't give it to you." (blocked)
- **`404 Not Found`**, "there's nothing here by that name."
- **`301`/`302`**, "go look at this other URL instead" (a *redirect*).

Learn to read these like a traffic light. In this challenge, the difference between `403` (blocked) and `404` (nothing there) is a genuine clue, not just noise, we'll use it in Part 4.

## 0.4 `curl`, seeing the raw truth

A browser is pretty but it hides things. `curl` is a command-line tool that sends one request and shows you exactly what came back, status code, headers, and body. The two flags you'll use constantly:

```bash
curl -i http://target/path     # -i = also show the response headers (incl. the status code)
curl -s http://target/path     # -s = silent (no progress bar), just the content
```

Whenever a browser "does something weird," drop to `curl` to see what's really happening.

## 0.5 What a QR code actually is

A **QR code** is just a picture that encodes *text*. That's it. A phone camera, an online reader, or a library like OpenCV reads the black/white squares back into the original string. The string can be a URL, a note, anything. The *colour* doesn't matter (ours is purple-on-black) as long as there's contrast. So "there's a QR in the image" really means "there's a hidden piece of text in the image."

## 0.6 Encoding vs. encryption vs. hashing (don't mix these up)

Three words beginners blur together, they're very different:

- **Encoding / obfuscation** (e.g. **ROT13**, Base64): a reversible *reshuffle* with **no secret key**. Anyone can undo it. It hides nothing from someone who recognises it. ROT13 just shifts each letter 13 places in the alphabet.
- **Encryption**: scrambling that needs a **secret key** to reverse. Without the key you're stuck.
- **Hashing** (e.g. **MD5**): a **one-way** fingerprint. You can turn `hello` into a hash, but you can't mathematically turn the hash back into `hello`, you can only *guess and check*.

This challenge uses ROT13 (encoding) for the path, and ends on an MD5 (a hash) as the "secret." Knowing which is which tells you what's even *possible*: ROT13 you simply reverse; an MD5 you can only try to crack by guessing.

---

# PART 1, The One Idea Behind This Whole Challenge

Injection boxes are about *data becoming instructions*. **Treasure-hunt / OSINT boxes are about a different single idea:**

> **"Hidden" usually means "not linked," not "actually protected." If you can learn the name of a thing, you can often just ask for it directly.**

Every step of this box is a variation on that. A path you weren't shown (but can decode). A directory you can't *list* (but whose files you can *name*). A hint sitting in a file meant for robots. The whole skill is **turning "I don't know it exists" into "I know its exact name"**, because once you know the name, the server hands it over.

Keep this lens. We'll use it at the image, the directory, and `robots.txt`.

---

# PART 2, The Image: Getting the Hidden Text Out

## 2.1 First, confirm what you're holding

Never assume. Ask the file what it is:
```bash
$ file quick_recovery.jpg
quick_recovery.jpg: JPEG image data, ... 3000x3000 ...
```
A big JPEG. Open it and you see a QR code. From Part 0.5 we know that means: **there's hidden text in here.**

## 2.2 A quick detour: is there *more* than the QR?

Images in CTFs sometimes hide extra data (this is **steganography**, "stego"). Two 10-second checks before you trust the QR as the whole story:

```bash
# 1) Is anything stuck on the END of the file, after the official JPEG end marker (FF D9)?
python3 -c "d=open('quick_recovery.jpg','rb').read(); i=d.rfind(b'\xff\xd9'); print('trailing bytes:', len(d)-(i+2))"
# → 0  (nothing appended)

# 2) Any human-readable strings worth a look (comments, URLs)?
strings quick_recovery.jpg | grep -iE 'flag|http|secret'
# → nothing meaningful
```
Both came back empty, so I stopped poking the file. (Learning to *rule things out* quickly is as valuable as finding things, it stops you wasting hours on a clean file.)

## 2.3 Decode the QR

Any reader works, your phone, an online decoder, or code. On the command line:
```bash
python3 -c "import cv2; print(cv2.QRCodeDetector().detectAndDecode(cv2.imread('quick_recovery.jpg'))[0])"
```
Out comes a note and a scrambled path:
```
Hey Jerry, ... Remember, from the root. ... piece everything together.
/VXarjLbhJbhyqSvaqGuvf
```

**Read the note like a puzzle-setter wrote it, because they did.** Two phrases are deliberate hints:
- *"from the root"*, this is telling you the cipher: **ROT** (short for rotation, a Caesar shift). It's also winking at the theme ("root").
- *"piece everything together"*, the answer is assembled from clues along the way; don't expect it handed to you.

---

# PART 3, The Cipher: Un-scrambling the Path

## 3.1 What ROT13 is

**ROT13** shifts every letter 13 positions along the alphabet (A→N, B→O, ...). Because the alphabet has 26 letters, applying it *twice* gets you back to the start, so the same operation both scrambles and unscrambles. There's no key; it's pure reshuffling (Part 0.6). The *"from the root" → ROT* hint is the puzzle telling you which of the many simple ciphers to try first.

## 3.2 Do it

```bash
$ python3 -c "import codecs; print('/' + codecs.decode('VXarjLbhJbhyqSvaqGuvf','rot13'))"
/IKnewYouWouldFindThis
```
Letter by letter, `V`→`I`, `X`→`K`, `a`→`n`... and you get `IKnewYouWouldFindThis`. **How do you know ROT13 was right?** Because the output is *readable English*. That's your confirmation, if a cipher guess produces gibberish, it was the wrong cipher or wrong shift. (If ROT13 *hadn't* worked, the next move is to try all 25 Caesar shifts, tools like CyberChef's "ROT13 Brute Force" do this in one click.)

So the hidden path is:
```
http://54.72.82.22:8010/IKnewYouWouldFindThis
```

---

# PART 4, The 403: A Wall That Isn't One

## 4.1 What happens when you visit it

```bash
$ curl -i http://54.72.82.22:8010/IKnewYouWouldFindThis/
HTTP/1.1 403 Forbidden
...
```
A beginner reads `403 Forbidden` as "locked, dead end, go home." **Don't.** You have to understand *why* a web server says `403` on a folder.

## 4.2 Directory listing, and why `403` here is a clue

When you ask for a *directory* (a folder, not a specific file), the server has to decide what to show you. It has two options:

1. **Show an index**, if there's an `index.html`, it shows that. If not, some servers show an **auto-generated list** of every file in the folder (that's "directory listing" / "autoindex").
2. **Refuse**, if the admin turned listing *off* (`Options -Indexes` in Apache) and there's no index file, the server has nothing it's willing to show you, so it answers **`403 Forbidden`**.

Here's the crucial part: that `403` is refusing to **list the folder's contents**. It is *not* refusing to serve the files inside. It's the difference between "I won't give you a map of this room" and "I won't let you touch anything in it." The files are still there, still served, *if you can name one*.

> **The mental shift:** `403` on a directory = "listing is off." It's an invitation to **guess filenames**, not a locked door.

## 4.3 So what filename do I guess?

You *could* blindly brute-force with a wordlist (tools: `ffuf`, `gobuster`), and that's a legit approach. But good challenges leave you the name. Ours does, in the next file.

---

# PART 5, `robots.txt`: The File That Gives It Away

## 5.1 What `robots.txt` is

`robots.txt` is a plain text file websites put at their root (`http://site/robots.txt`). It politely asks search-engine crawlers "please don't index these paths." Two things make it a hacker's best friend:

1. It's **public**, anyone can read it; it's just a URL.
2. The whole point of it is to **list the paths the owner doesn't want advertised**, which is often *exactly* the interesting stuff. (This is Part 1 in action: "hidden" = "asked nicely not to look," not "protected.")

Always read it on any web target:
```bash
$ curl -s http://54.72.82.22:8010/robots.txt
User-agent: *
Disallow: /IKnewYouWouldFindThis/
# Legacy recovery records use their original file paths.
```

## 5.2 Squeeze the clue dry

Three lines, two gifts:

- `Disallow: /IKnewYouWouldFindThis/`, confirms this is *the* directory (matches our decoded path). Reassuring: we're on the right trail.
- `# Legacy recovery records use their original file paths.`, a **comment**. The `#` means crawlers ignore it, but *you* don't. This is operational gossip the author left in. Decode what it's telling you:
  - *"recovery records"* → remember the file we started from? `quick_recovery.jpg`. The files here are "recovery"-style records.
  - *"their original file paths"* → they're at **predictable, standard names**, not random hashes.

Put it together with Part 4: **listing is off, but the files sit at ordinary guessable names.** That's a green light to guess.

---

# PART 6, Forced Browsing: Asking for the File by Name

## 6.1 The technique

**Forced browsing** (a.k.a. "forced browsing to an unlinked resource") is just: *requesting a file directly by its path even though nothing linked you to it.* No magic, you ask, the server answers `200` (here it is) or `404` (no such file).

The trick is telling hits from misses. From Part 0.3: a miss is `404`; a hit is `200`. We can also watch the response **size**, the `404` page is a fixed 315-byte Apache error, so anything a different size stands out. Let's loop over sensible guesses:

```bash
T=http://54.72.82.22:8010/IKnewYouWouldFindThis
for f in quick_recovery.jpg recovery.txt index.html flag.txt README.txt backup.zip; do
  echo "$(curl -s -o /dev/null -w '%{http_code} %{size_download}B' "$T/$f")  ->  $f"
done
```
`curl` flags decoded:
- `-o /dev/null`, throw away the body (we only want the verdict).
- `-w '%{http_code} %{size_download}B'`, print the status code and how many bytes came back.

Result:
```
404 315B  ->  quick_recovery.jpg
404 315B  ->  recovery.txt
404 315B  ->  index.html
200 40B   ->  flag.txt       <-- different! 200, and only 40 bytes
404 315B  ->  README.txt
404 315B  ->  backup.zip
```
`flag.txt` is the odd one out: `200`, 40 bytes. That's our file.

## 6.2 Read it

```bash
$ curl -s http://54.72.82.22:8010/IKnewYouWouldFindThis/flag.txt
safctf{69f779b5b18bad69606f1926395e7c2a}
```
**Done.** The directory's `403` never protected this file, it only hid the *list*. Once we knew the name, the server handed it over without hesitation. That's the whole lesson of the box.

## 6.3 About that MD5 inside the braces

`69f779b5b18bad69606f1926395e7c2a` is 32 hex characters, the shape of an **MD5 hash** (Part 0.6). People say "decrypt the MD5," but you can't *decrypt* a hash; it's one-way. You can only **crack** it, hash millions of candidate words and see if any produces the same fingerprint:
```bash
# easiest: paste it into crackstation.net
# or locally with a wordlist:
echo '69f779b5b18bad69606f1926395e7c2a' > hash.txt
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt   # -m 0 = MD5, -a 0 = wordlist
```
In this challenge the MD5 **is the secret/answer itself**, the "our secret" the QR note talked about, assembled at the end of the trail. Submitting the flag is the finish line; there's no further door behind the hash.

---

# PART 7, The Traps, and the Meta-Lessons

## 7.1 The decoys (and how to recognise bait)

The site dangles several shiny things that lead nowhere. Spotting and discarding bait is a core skill:

- **The login page (`/login.html`).** Looks like the obvious attack surface, a username/password form screams "brute-force me" or "SQL injection." But look at its code: `onsubmit="fakeLogin(event)"`, and `fakeLogin` just runs `alert("Sign-in was unsuccessful.")`. It **never sends a request** to any server. There's no backend, no database, nothing to attack. It's a painting of a door. *Lesson: a form is only an attack surface if it actually talks to a server, check before you spend an hour on it.*
- **`/js/ui.js`.** It literally comments itself: `// fake noisy widget values (for confusion)`. It only animates a fake "latency" number on the page. *Lesson: read the source of the scripts a page loads; sometimes the author tells you outright it's noise.*
- **The hidden QR image (`/assets/quick_recovery.jpg`, `display:none`).** The very QR you already solved, re-served and hidden on the page, to tempt you into re-analysing it for a "second layer." *Lesson: once you've fully extracted a clue, re-encountering it is a loop, not a lead.*

The real trail ignored every one of these. It was only ever: **image → ROT13 → robots.txt → guess `flag.txt`.**

## 7.2 The habits that actually solved it

Carry these to every web/OSINT box:

1. **Confirm what a file *is* before theorising** (`file`, then rule out stego fast). Don't burn time on a clean image.
2. **Read every clue as intentional.** "From the root" wasn't flavour text, it named the cipher. Puzzle authors choose words on purpose.
3. **A `403` on a directory means "listing is off," not "give up."** Pivot to guessing filenames.
4. **Always read `robots.txt`** (and `sitemap.xml`, and comments in any served file). The owner's "please don't look here" list is your to-do list.
5. **Learn the difference between encoding, encryption, and hashing**, it tells you what's even possible (reverse it vs. need a key vs. can only guess-and-check).
6. **Recognise bait.** If something is loudly interesting but goes nowhere, check whether it actually does anything before investing in it.

---

# Glossary

- **Client**, the program making the request (your browser or `curl`).
- **curl**, a command-line tool that sends one HTTP request and shows the raw response.
- **Directory listing (autoindex)**, a server auto-generating a browsable list of a folder's files when there's no index page. Turning it off (`Options -Indexes`) makes the server answer `403` for the folder, but files inside are still served by name.
- **Encoding / obfuscation**, a reversible reshuffle with no key (ROT13, Base64). Hides nothing from someone who recognises it.
- **Encryption**, scrambling that needs a secret key to reverse.
- **Forced browsing**, requesting a file/path directly by name even though nothing linked to it.
- **Hash (MD5)**, a one-way fingerprint of data. You can't reverse it; you can only crack it by guessing inputs and comparing.
- **HTTP**, the request/response language of the web.
- **Oracle**, any observable response that changes with your input, letting you tell hits from misses (here: `200` vs `404`, and the response size).
- **Port**, which numbered "door" on a server you connect to (web is usually 80; this box is 8010).
- **QR code**, an image that encodes text; a reader turns the squares back into the original string.
- **robots.txt**, a public file at a site's root listing paths crawlers should skip. A hint for robots, **not** an access control, and a goldmine for recon.
- **ROT13**, a Caesar cipher that shifts each letter 13 places; applying it twice returns the original. No key.
- **Status code**, the number summarising a response: `200` OK, `403` Forbidden, `404` Not Found, `301/302` redirect.
- **Steganography (stego)**, hiding data *inside* another file (e.g. bytes appended after a JPEG, or buried in pixels).
- **URL**, the full address of a resource: protocol + host + port + path.

---

# Where to Practise Next

- **Re-walk the trail yourself** from just the image: decode the QR, spot the "from the root" hint, ROT13 the path, read `robots.txt`, guess the file. Doing it unaided once cements the pattern.
- **Learn the two core tools you didn't *need* here but will soon:** `ffuf` and `gobuster` for brute-forcing directories and filenames when the author *doesn't* hand you the name in `robots.txt`.
- **Play with CyberChef** (an in-browser "swiss-army knife"), paste the scrambled path and try "ROT13", "ROT13 Brute Force", "Magic". It teaches you to recognise encodings on sight.
- **Look up:** the Robots Exclusion Standard, Apache's `Options -Indexes`, GTFOBins (for when boxes *do* go to shells), and the OWASP page on "Forced Browsing."

The goal isn't to memorise this one hunt. It's to internalise the idea underneath it, ***"hidden" usually means "unlinked," and a name you can learn is a thing you can fetch***, because most recon boxes are a new costume on that same idea.
