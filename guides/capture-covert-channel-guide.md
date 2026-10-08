# Masterclass: Reading a Covert-Channel pcap & Cracking the Keystream, From Zero

**Companion to:** `capture-covert-channel-writeup.md`

This one is **packet forensics + crypto**. The guide teaches, from zero: what a pcap actually is, how to open and triage a *non-IP* capture in **both Wireshark (GUI) and tshark (CLI)**, how to spot a covert channel hidden in noise, how to carve the structured signal frames out, and then the full method for **reconstructing an unknown XOR keystream**, including the specific insight (pad length = key length) that solved this box. Every GUI step has a `tshark` equivalent so you can do it either way.

---

## How to read this

- **Part 0**, what a pcap is, link-layer types, and the tools.
- **Part 1**, triage: is this even IP traffic? (Wireshark + tshark)
- **Part 2**, spotting the covert channel (IDLE vs LIVE).
- **Part 3**, carving the signal frames (GUI filters + CLI fields).
- **Part 4**, finding the key and confirming the cipher.
- **Part 5**, cracking the keystream: the methodology, and the "pad = key length" insight.
- **Part 6**, fixes / how you'd do it securely.
- **Glossary**.

---

# PART 0, What Is a pcap, and What Tools Do I Use?

A **pcap** ("packet capture") is a file of network frames recorded off a wire/interface. Each frame has a **link-layer type (DLT)** that says how to interpret its bytes, usually Ethernet, but captures can use other DLTs. This challenge uses **`USER 0`**, a "raw user-defined" link type: Wireshark won't dissect it into protocols, so **the frame payload is just bytes you interpret yourself.** That's exactly what makes it a hiding place.

Three tools (install `wireshark` / `tshark`):
- **Wireshark**, the GUI. Great for *browsing*, following streams, and visually spotting patterns.
- **tshark**, Wireshark's CLI. Great for *scripting* and piping bytes into Python.
- **capinfos**, one-line summary of a capture (packets, duration, DLT).

---

# PART 1, Triage: Is This Normal Traffic?

**Always characterise the capture before diving in.**

**CLI:**
```bash
capinfos capture.pcap            # packets, duration, File encapsulation
tshark -r capture.pcap -q -z io,phs   # protocol hierarchy
```
Here `capinfos` shows `File encapsulation: USER 0` and `87 packets / 86s` (≈1/sec), and the hierarchy is just `data`, **no TCP, no IP**. Translation: this isn't a network conversation to follow; it's a **custom byte stream** split into frames.

**GUI (Wireshark):**
- `Statistics → Capture File Properties` → see the encapsulation and packet count.
- `Statistics → Protocol Hierarchy` → confirms it's all "Data".
- The packet list shows no src/dst/protocol, another sign of a non-IP DLT.

> Heuristic: **steady 1-packet-per-second, fixed-ish sizes, and a non-IP DLT** scream "synthetic channel," not real traffic.

---

# PART 2, Spotting the Covert Channel

Look at the raw bytes of a few frames. In **Wireshark**, click a packet and read the **Packet Bytes** pane (bottom); the ASCII column on the right is the fast way to spot text markers. You'll immediately see two kinds of frame:

```
49 44 4c 45 …   ->  "IDLE" + random bytes     (most frames)
4c 49 56 45 …   ->  "LIVE" + structured bytes  (a few frames)
```

**CLI equivalent**, dump every frame's payload as hex and eyeball:
```bash
tshark -r capture.pcap -T fields -e data.data
```
`IDLE` and `LIVE` are ASCII tags (`49444c45`, `4c495645`). The pattern is a **covert channel**: a handful of **LIVE** (signal) frames hidden in a flood of **IDLE** (noise) frames. *The noise is deliberate, your first job is to separate signal from it.*

---

# PART 3, Carving the Signal Frames

**GUI filter**, show only the signal frames. Wireshark display filters can match bytes:
```
data.data[0:4] == 4c:49:56:45          # frames whose payload starts with "LIVE"
```
(or `frame contains "LIVE"`). Right-click a matching packet → **Follow → ... / Export Packet Bytes** to save the payloads.

**CLI**, filter and parse in one go:
```bash
tshark -r capture.pcap -T fields -e data.data | grep -i '^4c495645'
```

Each LIVE payload is structured. Decode the fields:
```
"LIVE" (4 bytes) | seq (2 bytes, big-endian) | len (2 bytes) | data (len bytes)
```
Parse and **reassemble by `seq`** (the frames arrive out of order in the capture; `seq` is the real order):

```python
import subprocess
rows = subprocess.check_output(
    ["tshark","-r","capture.pcap","-T","fields","-e","data.data"]).decode().split()
live = {}
for h in rows:
    b = bytes.fromhex(h)
    if b[:4] == b"LIVE":
        seq = int.from_bytes(b[4:6],"big")
        ln  = int.from_bytes(b[6:8],"big")
        live[seq] = b[8:8+ln]
ct = b"".join(live[s] for s in sorted(live))   # 44-byte ciphertext
```

The IDLE frames are dropped. (Confirm they're noise by XOR-decoding them too, they never produce readable text.)

---

# PART 4, Find the Key, Confirm the Cipher

Forensics challenges pair the capture with context files. Here, `session.log`:
```
19:02 replay card: afterglow-17
```
*"replay card"* → key material: **`afterglow-17`**. The ciphertext is high-entropy and we have a key hint → suspect **XOR with a keystream derived from the key** (the most common CTF construction is `SHA256(key)`).

**Confirm with known plaintext.** We expect the flag to start `safctf{`. XOR the first chunk against `SHA256(key)`:
```python
import hashlib
ks = hashlib.sha256(b"afterglow-17").digest()
print(bytes(ct[i]^ks[i] for i in range(7)))   # b'safctf{'  -> confirmed
```
A 7-byte hit on the known prefix proves both the key and that it's XOR-with-SHA256. **Known-plaintext is your anchor** for everything that follows.

---

# PART 5, Cracking the Keystream (the real skill)

The naive move, XOR the whole 44 bytes with the 32-byte digest, decodes cleanly for only **12 bytes** (`safctf{5554f`) then turns to garbage. The methodology for pushing past this:

### 5.1 Trust the math
A **12-byte (96-bit) clean run cannot be coincidence**, so the key is definitely right, and the keystream *is* `SHA256(key)` for those first 12 bytes. The only question is how the keystream behaves **after** byte 12. (Don't go re-guessing the key.)

### 5.2 Enumerate keystream shapes
When a hash-keystream decodes partially, methodically try the common constructions (a short script per family):
- **Continuous** full digest (what we did → 12 bytes).
- **Per-chunk reset** (`ks[0:len]` each frame).
- **Ratchet** (`H = SHA256(H)` each block).
- **Cipher feedback** (`SHA256(key + prev_block)`), CT- or PT-fed.
- **Truncated repeating pad** ← *the winner here.*

### 5.3 The decisive observation: where does it break?
The clean run was exactly **12 bytes**, and **`len("afterglow-17") == 12`**. When the break length equals the **key length**, the keystream is the hash **truncated to the key length and repeated** as a fixed pad:

```python
import hashlib
key = b"afterglow-17"
pad = hashlib.sha256(key).digest()[:len(key)]        # 12-byte pad
flag = bytes(ct[i] ^ pad[i % len(pad)] for i in range(len(ct)))
print(flag.decode())
# safctf{5554fd00-017a-4915-a883-a7ef2639f73b}
```

Clean, full-length flag. The body is a **UUID**, a reminder that **dashes/structure in decoded output can be real**; don't force it to look like pure hex.

### 5.4 Generalise it
Add a tiny "pad-length sweep" to your toolkit, try the keystream truncated to several lengths and print whichever is fully printable:
```python
for L in (7,8,12,16,20,24,32):
    pad = hashlib.sha256(key).digest()[:L]
    out = bytes(ct[i]^pad[i%L] for i in range(len(ct)))
    if all(32<=c<127 for c in out): print(L, out)
```
`L = len(key)` winning is a pattern worth remembering.

---

# PART 6, How You'd Do It Securely

- **Covert channel:** fine for CTF, but the signal/noise split (`LIVE`/`IDLE` markers) is trivially separable once spotted. Real hiding uses indistinguishable frames.
- **The cipher is the real flaw:** XOR with a **short, repeating, key-derived pad** is a *many-time pad*, catastrophic if reused, and here fully reversible because the key sits in a world-readable log. Use a real stream cipher (**ChaCha20**) with a **per-message nonce**, derive keys with a KDF, and never ship the key beside the ciphertext.

---

# Glossary

- **pcap**, a packet-capture file.
- **DLT / link type**, how a frame's bytes are interpreted; `USER 0` = raw/user-defined (no auto-dissection).
- **capinfos**, CLI tool summarising a capture.
- **tshark**, Wireshark's command-line twin; `-T fields -e data.data` prints frame payloads as hex.
- **Display filter**, Wireshark's in-GUI filter (e.g. `data.data[0:4]==4c:49:56:45`).
- **Covert channel**, hiding real data within innocuous-looking traffic/noise.
- **Known-plaintext**, using an expected substring (`safctf{`) to confirm a key/keystream.
- **Keystream**, the pseudorandom bytes XORed with plaintext in a stream cipher.
- **Repeating / truncated pad**, keystream shorter than the message, reused cyclically; weak.
- **UUID**, a `8-4-4-4-12` hex identifier (why the flag body had dashes).

---

# Where to Go Next

- Open other captures in **Wireshark**: practise `Statistics → Protocol Hierarchy`, `Follow Stream`, and byte-level display filters; learn to read the Packet Bytes pane fast.
- Script with **tshark `-T fields`** to pull exactly the bytes you want into Python.
- Build a keystream-cracking helper that sweeps constructions (continuous / per-chunk / ratchet / CFB / **truncated-pad**) against a known-plaintext anchor.
- Internalise the two lessons: **find the frame-type marker to split signal from noise**, and **when a hash-keystream breaks at exactly the key length, it's a repeating truncated pad.**

The transferable idea: **a capture you can't dissect is just bytes with structure you haven't found yet**, triage the container, separate signal from noise, anchor on known plaintext, then let *where the decode breaks* tell you how the keystream was built.
