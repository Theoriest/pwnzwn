# FINAL BOSS, 3-Stage Binary Reversing (XOR key · Caesar+Vigenère · token), My Writeup

| | |
|---|---|
| **Platform** | pwnzone (hosted CTF event) |
| **Target** | FINAL BOSS ("ENCORE" arcade, a downloadable binary + a 3-round web form) |
| **Service** | Flask on **Werkzeug/3.1.9**, Python 3.10.12, HTTP, TCP/8200 (EC2); challenge binary = x86-64 ELF |
| **IP:Port** | `54.72.82.22:8200` |
| **Artifacts** | `resources/finalboss.bin` (the downloadable binary) |
| **Flag format** | `safctf{...}` |
| **Date** | 2026-10-03 |
| **Outcome** | Reversed the ELF to recover three answers, stage-1 XOR key, stage-2 decrypted message (via gdb on the compare), stage-3 token, submitted them in-session to `/submit/stageN`, and got the flag. |
| **Honesty note** | Second-wave sweep. I worked it at the terminal (objdump/gdb). I'm keeping in the stage-2 pivot: rather than re-implement Caesar+Vigenère, I let the binary decrypt for me and read the answer off its own `strcmp`. |

---

## 1. The Short Version

FINAL BOSS hands you a binary ("Download Binary") and a web page with three locked rounds. Each round wants an answer; you get them by reverse-engineering `finalboss.bin`. The web side just validates and tracks progress via a session cookie, handing over the flag after stage 3.

The binary (not stripped) has three functions: `stage1_reverse_engineering`, `stage2_cryptography`, `stage3_exploitation`, plus a visible `STAGE3_TOKEN`.

- **Stage 1**, a 14-byte key is stored XOR-obfuscated; the code's own hint strings say `XOR_KEY_IS_0x42`, `LOOP_COUNT_14_BYTES`, `OPERATION_XOR_EACH_BYTE`. XOR the bytes with `0x42` → `R3v3rs3_M4st3r`.
- **Stage 2**, it shows ciphertext `Fvtsjcfw_1h_Q0a3iwua` and wants the Caesar+Vigenère decryption. Instead of reversing the math, I broke on the comparison in gdb and read the expected plaintext: `Overflow_1s_P0w3rful`.
- **Stage 3**, the token is the literal `STAGE3_TOKEN` string in `.rodata`: `3nc0r3_pwn3d_2025`.

Submit all three (same session) → flag.

**What I walked away with**

| Flag | Value | How |
|---|---|---|
| Flag | `safctf{a6aca5b356ad7824a01d0a767b2cd998}` | reverse 3 stages → submit to `/submit/stage{1,2,3}` with one session cookie |

Stage answers: `R3v3rs3_M4st3r` · `Overflow_1s_P0w3rful` · `3nc0r3_pwn3d_2025`.

---

## 1.1 Attack Chain

```mermaid
flowchart TD
    A["download finalboss.bin (ELF, not stripped)"] --> B["objdump: 3 stage functions"]
    B --> C1["stage1: 14 obfuscated bytes<br/>hints: XOR 0x42, 14 bytes"]
    C1 --> D1["XOR each ^0x42 → R3v3rs3_M4st3r"]
    B --> C2["stage2: cipher Fvtsjcfw_1h_Q0a3iwua<br/>(Caesar+Vigenère)"]
    C2 --> D2["gdb break on strcmp →<br/>expected = Overflow_1s_P0w3rful"]
    B --> C3[".rodata STAGE3_TOKEN]
    C3 --> D3["3nc0r3_pwn3d_2025"]
    D1 --> S["/submit/stage1"]
    D2 --> S2["/submit/stage2"]
    D3 --> S3["/submit/stage3 (same session)"]
    S --> S2 --> S3 --> R["🏁 safctf{...}"]

    classDef flag fill:#1a3a1a,stroke:#4caf50,color:#e0ffe0;
    classDef vuln fill:#3a1a1a,stroke:#e57373,color:#ffe0e0;
    class R flag;
    class D1,D2,D3 vuln;
```

---

## 2. Weaknesses I Used

| # | What | Class | Where | Severity |
|---|---|---|---|---|
| 1 | Secrets/keys embedded in a distributed, unstripped binary | **Reverse engineering of embedded secrets** (CWE-656 "security through obscurity") | `finalboss.bin` | n/a (challenge-by-design) |
| 2 | Expected plaintext computed then compared in-process | Dynamic-analysis leak (observe the `strcmp`) | `stage2_cryptography` |, |

(These aren't "web vulns", it's a RE challenge, but the lessons about not trusting the client/binary with secrets are the same as the rest of the dojo.)

---

## 3. Recon

```bash
curl -s -o finalboss.bin http://54.72.82.22:8200/download
file finalboss.bin    # ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped
nm finalboss.bin | grep -iE 'stage|main'
# 401256 T stage1_reverse_engineering
# 401768 T stage2_cryptography
# 401a14 T stage3_exploitation
# 401b1e T main
```

The web page's JS: each round POSTs `{answer}` to `/submit/<stage>`; a correct submit unlocks the next, and stage 3 returns `{flag}`. So the work is entirely in the binary; the server just gates and records progress (per **session cookie**, which matters later).

Strings gave the plan away:

```bash
strings -n5 finalboss.bin | grep -iE 'stage|xor|key|encrypt|token|congrat'
# === STAGE 1: REVERSE ENGINEERING ===   Enter the key:
# === STAGE 2: CRYPTOGRAPHY ===          Encrypted message: %s
# Congratulations! ...  Your Stage 3 token: %s
# STAGE3_TOKEN  stage1_reverse_engineering  stage2_cryptography  stage3_exploitation
```

---

## 4. The Exploit (per stage)

### 4.1 Stage 1, XOR-obfuscated key

`objdump -d` on `stage1_reverse_engineering` showed the obfuscated key loaded as immediates, plus three *hint* strings the code builds on the stack:

- `XOR_KEY_IS_0x42`
- `LOOP_COUNT_14_BYTES`
- `OPERATION_XOR_EACH_BYTE`

So the real key = 14 stored bytes each XORed with `0x42`. The stored bytes (little-endian immediates):

```python
import struct
b = struct.pack('<Q',0x1d71313071347110) + struct.pack('<I',0x3631760f) + struct.pack('<H',0x3071)
print(''.join(chr(c ^ 0x42) for c in b))
# R3v3rs3_M4st3r
```

```bash
curl -s -X POST http://54.72.82.22:8200/submit/stage1 \
  -H 'Content-Type: application/json' --data '{"answer":"R3v3rs3_M4st3r"}'
# ✓ Stage 1 Complete! ... hint: Stage 2 uses both Caesar and Vigenère ciphers.
```

### 4.2 Stage 2, let the binary decrypt for me

Stage 2 prints ciphertext `Fvtsjcfw_1h_Q0a3iwua` and wants the decrypted text. The hint says Caesar + Vigenère, but I don't know the shift or the Vigenère key. Rather than reverse the crypto routine by hand, I noticed the binary itself computes the expected plaintext and then `strcmp`s it against my input. So I let it do the work and **read the comparison** under gdb:

```bash
objdump -d -M intel finalboss.bin | grep -A2 strcmp   # strcmp call in stage2 at 0x401946
cat > cmds <<'EOF'
set pagination off
break *0x401946
run
printf "arg1=%s\n", (char*)$rdi
printf "arg2=%s\n", (char*)$rsi
EOF
printf 'R3v3rs3_M4st3r\nGUESS\nX\n' | gdb -q -x cmds ./finalboss.bin | grep arg
# arg1=GUESS
# arg2=Overflow_1s_P0w3rful   ← the expected (decrypted) plaintext
```

`arg2` is the server's expected answer, no crypto re-implementation needed:

```bash
curl -s -X POST .../submit/stage2 --data '{"answer":"Overflow_1s_P0w3rful"}'
# ✓ Stage 2 Complete!
```

### 4.3 Stage 3, the token hiding in `.rodata`

The `STAGE3_TOKEN` symbol pointed straight at a `.rodata` string:

```bash
objdump -s -j .rodata finalboss.bin | grep -A1 402010
# 402010  336e6330 72335f70 776e3364 5f323032   3nc0r3_pwn3d_202
# 402020  35...                                  5
# → 3nc0r3_pwn3d_2025
```

### 4.4 Submit all three in one session

My first submits failed with *"complete Stage 1 first"*, the server tracks progress in the **session cookie**, and I'd been firing stateless curls. Threading one cookie jar through fixed it:

```bash
J=jar; curl -s -c $J http://54.72.82.22:8200/ -o /dev/null
curl -s -c $J -b $J -X POST .../submit/stage1 --data '{"answer":"R3v3rs3_M4st3r"}'
curl -s -c $J -b $J -X POST .../submit/stage2 --data '{"answer":"Overflow_1s_P0w3rful"}'
curl -s -c $J -b $J -X POST .../submit/stage3 --data '{"answer":"3nc0r3_pwn3d_2025"}'
# {"flag":"safctf{a6aca5b356ad7824a01d0a767b2cd998}","success":true}
```

---

## 5. Why It Worked & How I'd Fix It

- **Everything was in the binary.** Keys, the crypto's expected output, and the token all live in a file that's *handed to the attacker*. That's security-through-obscurity: shipping a secret in a client artifact means shipping the secret. (Same lesson as VELVET ROOM's JS key and COMEBACK KIT's APK string.)
- **The compare leaked the answer.** Computing the expected value and `strcmp`-ing it means a debugger reads it for free, classic *dynamic analysis beats static obfuscation*.

How you'd defend a real program (and why CTFs set these up):

1. Don't embed secrets in client binaries; validate against a server you control.
2. If you must check locally, **compare hashes**, not the plaintext, so the debugger sees only a digest.
3. Strip symbols, add anti-debug/obfuscation, raises the bar but never stops a determined reverser.

---

## 6. Timeline

- Downloaded binary → `nm`/strings → three stages mapped.
- Stage 1: hint strings → XOR 14 bytes with `0x42` → `R3v3rs3_M4st3r`.
- Stage 2: gdb break on `strcmp` → read `Overflow_1s_P0w3rful` (skipped re-doing the cipher).
- Stage 3: `.rodata` `STAGE3_TOKEN` → `3nc0r3_pwn3d_2025`.
- Submitted all three with one session cookie → flag.

---

## 7. References

- `objdump`, `nm`, `gdb` manuals; **pwndbg**/**gef** for friendlier gdb
- Vigenère & Caesar ciphers (background for stage 2)
- CWE-656 (Reliance on Security Through Obscurity)

**Lesson I'm keeping:** when a binary *computes* the right answer to compare it, don't re-derive the math, **break on the compare and read it.** And remember the server's state: thread the session cookie or every "complete stage 1 first" is on you.
