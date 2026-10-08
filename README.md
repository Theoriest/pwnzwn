# pwnzone, CTF Challenge Index

Host: **`54.72.82.22`** (AWS EC2). Each challenge is a separate web app on its own port.
Flag format: `safctf{...}`. Author: **lacmyst**. Documented: 2026-10-02.

Each challenge has a first-person **writeup** (how I solved it, detours included) and a from-zero **guide/masterclass** (the techniques explained).

## Folder layout

```
pwnzone/
├── README.md        ← this index
├── writeups/        ← per-challenge first-person solves (*-writeup.md)
├── guides/          ← per-technique masterclasses (*-guide.md)
└── resources/       ← challenge materials
    ├── field-notes/  lastram/  bluemeridian/   (OSINT datasets)
    ├── capture.pcap  session.log               (packet-forensics challenge)
    ├── listening-room/                          (SQLite-WAL forensics: library.db + -wal/-shm)
    └── quick_recovery.jpg  traveller.avif  hash.txt  +screenshots (vinyl-vault-burp.png, matchday_replay.png, AI_response.png, AI_answer.png)
```

---

## Solved

| #   | Challenge                            | Port | Stack                                            | Core technique                                                                                                                           | Flag                                           |
| --- | ------------------------------------ | ---- | ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| 1   | **AFTERHOURS**                       | 8010 | Apache 2.4.68 (static)                           | QR decode → **ROT13** path → `robots.txt` leak → **forced browsing** a listing-disabled dir                                              | `safctf{69f779b5b18bad69606f1926395e7c2a}`     |
| 2   | **SIDE QUEST**                       | 8030 | Flask / Werkzeug                                 | **Parameter fuzzing** → **LFI / path traversal** (`?page=`) → read `/proc/self/environ`                                                  | `safctf{9fdb535dbf8020d488bf8d6a51287778}`     |
| 3   | **ROSTER HQ**                        | 8070 | Flask / Werkzeug                                 | **LDAP injection** auth bypass (`admin)(&)`) → authenticated `/audit-export`                                                             | `safctf{ef30111b835006ade7f00a9a4526d453}`     |
| 4   | **JWT `alg:none`**                   | 8100 | Express (Node.js)                                | **JWT forgery**, `alg:none`, forge `role:admin` → `/admin`                                                                              | `safctf{1e4d7bdea93b47c2a813ea5a89f20870}`     |
| 5   | **POLE POSITION**                    | 8060 | Flask / Werkzeug                                 | **SQL injection** auth bypass (`admin'-- -`) → flag shown to admin                                                                       | `safctf{30f33ad5be8abc02f034b5b266ff6b81}`     |
| 6   | **VINYL VAULT**                      | 8180 | Flask / Werkzeug                                 | **Privesc via spoofed IP header**, `X-Real-IP: 127.0.0.1` on `/admin` (decoys: `access_level`, `X-Forwarded-For`)                       | `safctf{e657eef1b0b097c60911f62cfe4ec61b}`     |
| 7   | **RELIC SOCIETY**                    | 8230 | **Java** (`app.jar`; Werkzeug header is a front) | **XXE**, reflected external entity → file read; list dirs → randomized flag file                                                        | `safctf{960c0e8a73c24bd9b1aee314ded96157}`     |
| 8   | **PAPER LANTERNS** (field notes)     | 8480 | Flask / Werkzeug                                 | **OSINT data correlation**, postcard riddle → unique record `ref=ba57ce94e3` → submit                                                   | `safctf{38309964a77c499b1ec234c401f68fe1}`     |
| 9   | **LAST TRAM HOME** (lastram)         | 8490 | Flask / Werkzeug                                 | **OSINT + SHA256 receipt**, `SHA256(venue\|event\|UTC_date)`                                                                            | `safctf{a7290ed4a3ba7af7bd4b4c529eb99314}`     |
| 10  | **BLUE MERIDIAN** (bluemeridian)     | 8500 | Flask / Werkzeug                                 | **OSINT + SHA256 receipt**, multi-file join, collision break → `SHA256(voyage\|station\|UTC_time)`                                      | `safctf{756f7d81426571a6d6dac9b1aae5f271}`     |
| 11  | **CAPTURE** (pcap)                   | file | USER-DLT pcap + session.log                      | **Packet forensics + XOR**, carve LIVE frames from IDLE noise → XOR with `SHA256("afterglow-17")[:12]` repeating pad                    | `safctf{5554fd00-017a-4915-a883-a7ef2639f73b}` |
| 12  | **SECOND PRESSING** (listening-room) | 8460 | Flask + SQLite bundle                            | **SQLite-WAL forensics**, recover "withdrawn" value from `-wal` → base64+zlib (`eJw…`) → flag is the recovered value                    | `safctf{12bbc51d-7450-44c6-af3f-1723514b8aad}` |
| 13  | **NIGHT BUS**                        | 8330 | Flask API                                        | **IDOR / predictable object id**, object = `sha256(reference)[:24]` → compute TOUR-2402's object                                        | `safctf{81a90dc817371a5aa190e8069ebcde2c}`     |
| 14  | **HARBOR LIGHTS**                    | 8390 | Flask object-store                               | **Path-normalization scope bypass (TOCTOU)**, `?key=public/../finance/final.txt` escapes `public/*`                                     | `safctf{0a7fe9c5e49d7fbe62cea634195d0adf}`     |
| 15  | **STAGEWORKS**                       | 8400 | Flask (STS-style API)                            | **Assume-role + session-tag forgery**, leaked `externalId` + self-asserted `department=finance` tag → tag-gated object                  | `safctf{b9d2678027feea5870c41931b663fd6d}`     |
| 16  | **ECHO COMPANION**                   | 8190 | Flask "AI" `/ask`                                | **Prompt injection / trigger-phrase leak**, the word `recall` unlocks the secret                                                        | `safctf{d432e09718e6cb46387f54e27dbc0168}`     |
| 17  | **MOONLIGHT CLUB**                   | 8020 | Flask / Jinja2                                   | **SSTI → RCE**, `{{7*7}}`→`49`; `lipsum.__globals__['os'].popen()` as root                                                              | `safctf{ac4c0d4a503d4ef281530c5ca9dc8fa4}`     |
| 18  | **PLAYER ONE**                       | 8040 | Flask / Jinja2                                   | **SSTI → RCE**, same `lipsum.__globals__` pivot                                                                                         | `safctf{287a681f8f9aa898e0743b5b392952b0}`     |
| 19  | **CITRUS STUDIO**                    | 8050 | Flask / Jinja2                                   | **SSTI → RCE + filter bypass**, `__`/`config`/`'os'` blocked → `attr('_'+'_globals_'+'_')`, `'o'+'s'`                                   | `safctf{42dd8c3f359acdfc9b4250f4864ffc35}`     |
| 20  | **ORBIT DISPATCH**                   | 8080 | Flask (URL fetcher)                              | **SSRF past a blocklist**, decimal IP `2130706433` → internal `:9000/flag` (IMDS also reachable)                                        | `safctf{9f3a458f3a26e6372b5b5467e3e51edf}`     |
| 21  | **THE VELVET ROOM**                  | 8090 | Flask + SQLite                                   | **SQLi auth bypass past a WAF**, TAB-smuggled `OR` → `/vault` → AES decrypt w/ JS-leaked key                                            | `safctf{7877e854c9f06a8362af26ee280a6574}`     |
| 22  | **DEEP BLUE RADIO**                  | 8120 | Flask + LLM                                      | **LLM prompt injection**, "secret treasure code" + **base64** dodges in/out "flag"/"safctf" filters                                     | `safctf{4d19e2980e16abb93f0ff0481e4729e1}`     |
| 23  | **COMEBACK KIT**                     | 8130 | Apache (static)                                  | **Exposed backup**, `/backup.zip` (Android project) → flag in `res/values/archive.xml`                                                  | `safctf{94f40cc66658c67503a859cf383c7622}`     |
| 24  | **THE DAILY SCOOP**                  | 8140 | Apache/PHP + **PostgreSQL**                      | **UNION SQLi**, single-column `UNION`; dump `super_secret::text` (row cast dodges column filter)                                        | `safctf{73c4979d1dccb358dbfbaca5233666ca}`     |
| 25  | **OFF THE WALL**                     | 8160 | Apache/PHP                                       | **Unrestricted upload → RCE**, PHP webshell in `/uploads/` as www-data                                                                  | `safctf{059507cb1ce1b9fa4dbf4ad6cfb83a4a}`     |
| 26  | **FINAL BOSS**                       | 8200 | Flask + ELF binary                               | **Binary reversing (3 stages)**, XOR-0x42 key, Caesar+Vigenère (gdb `strcmp`), `.rodata` token                                          | `safctf{a6aca5b356ad7824a01d0a767b2cd998}`     |
| 27  | **TOUCHLINE DISPATCH**               | 8300 | Flask (desk API)                                 | **Path traversal**, `/api/view?name=/proc/self/environ` → `FLAG`; `....//` beats the `../` filter; source leak too                      | `safctf{276928973c4dea42f63d808ba7be66b7}`     |
| 28  | **VELVET REHEARSAL**                 | 8310 | Flask (desk API)                                 | **HTTP parameter pollution**, `?member=visitor&member=director` → director token in visitor mailbox → `/api/entry`                      | `safctf{1745c9cc8a433522796feb9cfb8275de}`     |
| 29  | **BACKSTAGE LEDGER**                 | 8340 | Flask (desk API)                                 | **Mass assignment / key-traversal**, PATCH `{"profile":{"../role":"producer"}}` escapes into user → `/api/settlement`                   | `safctf{414329f08fe10f2027b4afeb2e5bba9b}`     |
| 30  | **THREE ENCORES**                    | 8420 | Flask (desk; file challenge)                     | **Low-exponent RSA**, `e=3`, `m³ < n` (un-reduced) → integer cube root of `c` → recovered value is the flag (`/submit` = ack, not flag) | `safctf{dadb56ae-eede-422e-87cb-744462cdfda0}` |

## Files

| Challenge | Writeup | Guide / Masterclass |
|---|---|---|
| AFTERHOURS | [afterhours-qr-recovery-writeup.md](writeups/afterhours-qr-recovery-writeup.md) | [afterhours-qr-recovery-guide.md](guides/afterhours-qr-recovery-guide.md) |
| SIDE QUEST | [sidequest-page-lfi-writeup.md](writeups/sidequest-page-lfi-writeup.md) | [sidequest-page-lfi-guide.md](guides/sidequest-page-lfi-guide.md) |
| ROSTER HQ | [rosterhq-ldap-injection-writeup.md](writeups/rosterhq-ldap-injection-writeup.md) | [rosterhq-ldap-injection-guide.md](guides/rosterhq-ldap-injection-guide.md) |
| JWT `alg:none` | [jwt-alg-none-writeup.md](writeups/jwt-alg-none-writeup.md) | [jwt-alg-none-guide.md](guides/jwt-alg-none-guide.md) |
| POLE POSITION | [poleposition-sqli-writeup.md](writeups/poleposition-sqli-writeup.md) | [poleposition-sqli-guide.md](guides/poleposition-sqli-guide.md) |
| VINYL VAULT | [vinylvault-header-spoof-writeup.md](writeups/vinylvault-header-spoof-writeup.md) | [vinylvault-header-spoof-guide.md](guides/vinylvault-header-spoof-guide.md) |
| RELIC SOCIETY | [relicsociety-xxe-writeup.md](writeups/relicsociety-xxe-writeup.md) | [relicsociety-xxe-guide.md](guides/relicsociety-xxe-guide.md) |
| OSINT DESK (PAPER LANTERNS + LAST TRAM HOME + BLUE MERIDIAN) |, (consolidated into the guide) | [osint-sha256-receipts-guide.md](guides/osint-sha256-receipts-guide.md) |
| TOUCHLINE DISPATCH | [touchline-path-traversal-writeup.md](writeups/touchline-path-traversal-writeup.md) | [sidequest-page-lfi-guide.md](guides/sidequest-page-lfi-guide.md) |
| VELVET REHEARSAL | [velvetrehearsal-hpp-writeup.md](writeups/velvetrehearsal-hpp-writeup.md) | [http-parameter-pollution-guide.md](guides/http-parameter-pollution-guide.md) |
| BACKSTAGE LEDGER | [backstageledger-mass-assignment-writeup.md](writeups/backstageledger-mass-assignment-writeup.md) | [mass-assignment-key-traversal-guide.md](guides/mass-assignment-key-traversal-guide.md) |
| THREE ENCORES | [threeencores-rsa-cuberoot-writeup.md](writeups/threeencores-rsa-cuberoot-writeup.md) | [rsa-low-exponent-guide.md](guides/rsa-low-exponent-guide.md) |
| CAPTURE (pcap) | [capture-covert-channel-writeup.md](writeups/capture-covert-channel-writeup.md) | [capture-covert-channel-guide.md](guides/capture-covert-channel-guide.md) |
| SECOND PRESSING (listening-room) | [listening-room-sqlite-wal-writeup.md](writeups/listening-room-sqlite-wal-writeup.md) | [listening-room-sqlite-wal-guide.md](guides/listening-room-sqlite-wal-guide.md) |
| NIGHT BUS | [nightbus-idor-writeup.md](writeups/nightbus-idor-writeup.md) | [nightbus-idor-guide.md](guides/nightbus-idor-guide.md) |
| HARBOR LIGHTS | [harborlights-path-bypass-writeup.md](writeups/harborlights-path-bypass-writeup.md) | [harborlights-path-bypass-guide.md](guides/harborlights-path-bypass-guide.md) |
| STAGEWORKS | [stageworks-assume-role-writeup.md](writeups/stageworks-assume-role-writeup.md) | [stageworks-assume-role-guide.md](guides/stageworks-assume-role-guide.md) |
| ECHO COMPANION | [echo-companion-prompt-injection-writeup.md](writeups/echo-companion-prompt-injection-writeup.md) | [echo-companion-prompt-injection-guide.md](guides/echo-companion-prompt-injection-guide.md) |
| SSTI TRIO (MOONLIGHT CLUB · PLAYER ONE · CITRUS STUDIO) | [ssti-greeting-trio-writeup.md](writeups/ssti-greeting-trio-writeup.md) | [ssti-jinja2-rce-guide.md](guides/ssti-jinja2-rce-guide.md) |
| ORBIT DISPATCH | [orbitdispatch-ssrf-writeup.md](writeups/orbitdispatch-ssrf-writeup.md) | [ssrf-masterclass-guide.md](guides/ssrf-masterclass-guide.md) |
| THE VELVET ROOM | [velvetroom-sqli-writeup.md](writeups/velvetroom-sqli-writeup.md) | [sqli-waf-bypass-guide.md](guides/sqli-waf-bypass-guide.md) |
| DEEP BLUE RADIO | [deepblue-llm-injection-writeup.md](writeups/deepblue-llm-injection-writeup.md) | [llm-prompt-injection-guide.md](guides/llm-prompt-injection-guide.md) |
| COMEBACK KIT | [comebackkit-exposed-backup-writeup.md](writeups/comebackkit-exposed-backup-writeup.md) | [exposed-files-content-discovery-guide.md](guides/exposed-files-content-discovery-guide.md) |
| THE DAILY SCOOP | [dailyscoop-postgres-sqli-writeup.md](writeups/dailyscoop-postgres-sqli-writeup.md) | [union-sqli-postgres-guide.md](guides/union-sqli-postgres-guide.md) |
| OFF THE WALL | [offthewall-upload-rce-writeup.md](writeups/offthewall-upload-rce-writeup.md) | [file-upload-rce-guide.md](guides/file-upload-rce-guide.md) |
| FINAL BOSS | [finalboss-reversing-writeup.md](writeups/finalboss-reversing-writeup.md) | [binary-reversing-guide.md](guides/binary-reversing-guide.md) |
| FAN SIGNAL (partial) | [fansignal-xss-writeup.md](writeups/fansignal-xss-writeup.md) | [xss-masterclass-guide.md](guides/xss-masterclass-guide.md) |

Challenge materials live in [`resources/`](resources/), e.g. `resources/quick_recovery.jpg` (the AFTERHOURS QR code), the OSINT datasets, and `resources/vinyl-vault-burp.png`.

---

## Techniques covered (quick reference)

- **OSINT / recon:** reading page source for hidden elements, QR decoding, `robots.txt`, directory vs. file access, **forced browsing**.
- **Ciphers:** ROT13 / Caesar (encoding ≠ encryption).
- **Fuzzing:** `ffuf` for **paths** *and* **parameter names** (`/?FUZZ=test -fs <baseline>`).
- **LFI / path traversal:** `../` breakout, `/proc/self/{environ,cmdline,cwd}` for secrets & app layout.
- **LDAP injection:** filter-breakout auth bypass; SQLi-vs-LDAPi tells ("Directory" → LDAP).
- **JWT:** `alg:none` forgery; plus the family (weak-secret cracking, RS256→HS256 key confusion, `kid` injection).
- **Access control / privesc:** trusting client-controlled headers (`X-Real-IP`/`X-Forwarded-For` spoof to `127.0.0.1`), client-set privilege fields (`access_level`), spotting decoys.
- **XXE:** reflected external-entity file read; the XML-char limitation and the directory-listing workaround; parser fingerprinting (Java `file://` listing); OOB/blind XXE.
- **OSINT:** data correlation across files (prose riddle → structured filters → unique join); opaque IDs aren't ciphertext.
- **Packet forensics / crypto:** reading non-IP (USER-DLT) pcaps in Wireshark/tshark; separating covert signal (LIVE) from noise (IDLE); reconstructing an XOR keystream via known-plaintext; the "pad length = key length" tell.
- **DB forensics:** recovering overwritten rows from the SQLite **WAL**; base64/zlib signatures (`eJw…`); the rule *never checkpoint your evidence* (copy first, read WAL raw).
- **IDOR / broken object-level auth:** recognising predictable ids (fake ObjectId via its 1991 timestamp); proving `object = sha256(reference)[:24]` from a known pair; deriving another object; the "default-for-unknown-id" trap.
- **Path traversal / TOCTOU scope bypass:** authorize-then-normalize bugs; `../` encodings that are equivalent (`%2e`/`%2f`/case) vs. ones that aren't (`\`, over-traversal); reading the "resolved-inside-scope" decoy oracle.
- **Cloud IAM / assume-role abuse:** confused-deputy `externalId` (and leaking it in deploy logs); forging self-asserted **session tags** that gate authorization; spotting it in IAM trust policies / code / black-box.
- **LLM / prompt injection:** trigger-phrase & refusal-mining; direct/indirect injection taxonomy; telling a real LLM from a keyword bot; why in-prompt guardrails fail; **beating in/out filters by encoding** (ask for the secret base64'd so `safctf` never appears, synonym for the blocked word).
- **SSTI (Server-Side Template Injection):** `{{7*7}}`→`49` detection & engine fingerprinting; Jinja2 `lipsum.__globals__['os'].popen()` RCE; enumerate the context instead of cargo-culting `cycler`; **filter bypass** with `attr()` + string concatenation (`'_'+'_globals_'+'_'`, `'o'+'s'`).
- **SSRF (Server-Side Request Forgery):** loopback/metadata as the prize; **blocklist bypass by IP representation** (decimal `2130706433` = `127.0.0.1`); loopback port-scanning through the fetcher; EC2 IMDS; resolve-and-pin as the fix.
- **SQLi, WAF bypass & UNION enumeration:** **whitespace smuggling** (real TAB between `OR` and operands) past a space-anchored keyword WAF; reading the whole response (don't trust keyword "success"); **UNION-based extraction on PostgreSQL** (`ORDER BY` column count, `information_schema`, `string_agg`, `table::text` row cast to dodge column filters).
- **Exposed files / content discovery:** `/backup.zip`, `.git`, `.env`, source/config leaks; `ffuf -e .zip,.bak,.sql`; 403-means-exists; secrets in client artifacts (JS keys, APK strings, leaked DSNs).
- **Unrestricted file upload → RCE:** the two conditions (controllable extension/content **and** an executable landing dir); PHP webshell; extension/MIME/magic-byte bypasses; cleanup & ethics.
- **XSS (reflected):** raw-reflection detection, XSS-vs-SSTI, injection-context payloads, the victim-bot delivery model and cookie/internal-page exfiltration; CSP + output encoding + HttpOnly as fixes.
- **Binary reversing:** ELF/sections/symbols; `strings`/`objdump`/`nm`; decoding packed little-endian immediates; the **break-on-`strcmp`** trick (read the expected value instead of reversing the crypto); XOR de-obfuscation.
- **HTTP parameter pollution:** repeating a param so two code paths read different occurrences (`getlist` indexed `[0]` vs `[-1]`); first-vs-last divergence; per-stack duplicate resolution; broken password-recovery via a token delivered to the wrong account.
- **Mass assignment / key-traversal:** merging attacker keys into a server object to write a privilege field; a nested `../role` key escaping the one object you were "allowed" to edit (dict cousin of path traversal; see also JS prototype pollution); allowlist-exact-fields as the fix.
- **Source leak as a master key:** one path-traversal read of `/proc/self/cwd/service.py` exposed the shared `dispatch()` for the whole desk block, turning later challenges into one-shot solves. Also `/proc/self/environ` for the `FLAG` env var.
- **Low-exponent RSA:** `e=3` with a short/unpadded message so `m³ < n` → ciphertext is a plain cube → integer cube root recovers `m`; the tell is identical `c` across different `n`. Håstad broadcast (CRT + cube root) when the ciphertexts differ. Fix = OAEP + `e=65537`.
- **Tooling:** `curl` (`-i/-L/-b/-c/--data-urlencode`), `ffuf`, `binwalk`, `jwt_tool`, `hashcat`/`john`, SecLists.

---

## Port map (observed)

| Port | State    | Notes                                                                                                                         |
| ---- | -------- | ----------------------------------------------------------------------------------------------------------------------------- |
| 8000 | **down** | `Connection refused`, nothing listening (not firewalled; just not deployed)                                                   |
| 8010 | up       | AFTERHOURS (solved)                                                                                                           |
| 8020 | up       | MOONLIGHT CLUB, SSTI (solved)                                                                                                 |
| 8030 | up       | SIDE QUEST (solved)                                                                                                           |
| 8040 | up       | PLAYER ONE, SSTI (solved)                                                                                                     |
| 8050 | up       | CITRUS STUDIO, SSTI + filter bypass (solved)                                                                                  |
| 8060 | up       | POLE POSITION (solved)                                                                                                        |
| 8070 | up       | ROSTER HQ (solved)                                                                                                            |
| 8080 | up       | ORBIT DISPATCH, SSRF (solved)                                                                                                 |
| 8090 | up       | THE VELVET ROOM, SQLi/WAF bypass + crypto (solved)                                                                            |
| 8100 | up       | JWT box (solved)                                                                                                              |
|      |          |                                                                                                                               |
| 8120 | up       | DEEP BLUE RADIO, LLM prompt injection (solved)                                                                                |
| 8130 | up       | COMEBACK KIT, exposed backup (solved)                                                                                         |
| 8140 | up       | THE DAILY SCOOP, PostgreSQL UNION SQLi (solved)                                                                               |
|      |          |                                                                                                                               |
| 8160 | up       | OFF THE WALL, upload RCE (solved)                                                                                             |
| 8180 | up       | VINYL VAULT (solved)                                                                                                          |
| 8190 | up       | ECHO COMPANION (solved)                                                                                                       |
| 8200 | up       | FINAL BOSS, binary reversing (solved)                                                                                         |
| 8210 | up       | FRAME / FOUND, **in progress** (OpenSSL `archive.tar.gz.enc`; password = weak word via photo EXIF hint; rockyou brute paused) |
| 8220 | up       | FAN SIGNAL, reflected XSS **confirmed**, flag blocked on victim-bot infra (partial)                                           |
| 8230 | up       | RELIC SOCIETY (solved)                                                                                                        |
| 8240 | up       | **Apache Tomcat/9.0.122**, root 404; Java/Tomcat challenge, needs path/app enumeration (unsolved)                             |
| 8300 | up       | TOUCHLINE DISPATCH, path traversal (solved)                                                                                   |
| 8310 | up       | VELVET REHEARSAL, HTTP parameter pollution (solved)                                                                           |
| 8330 | up       | NIGHT BUS (solved)                                                                                                            |
| 8340 | up       | BACKSTAGE LEDGER, mass assignment / key-traversal (solved)                                                                    |
|      |          |                                                                                                                               |
| 8390 | up       | HARBOR LIGHTS (solved)                                                                                                        |
| 8400 | up       | STAGEWORKS (solved)                                                                                                           |
| 8420 | up       | THREE ENCORES, low-exponent RSA cube root (solved)                                                                            |
| 8460 | up       | SECOND PRESSING / listening-room (solved)                                                                                     |
| 8480 | up       | PAPER LANTERNS / field notes (solved)                                                                                         |
| 8490 | up       | LAST TRAM HOME / lastram (solved)                                                                                             |
| 8500 | up       | BLUE MERIDIAN / bluemeridian (solved)                                                                                         |

