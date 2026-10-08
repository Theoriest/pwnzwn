# Masterclass: Reversing a Linux Binary, Static + Dynamic, From Zero

The skills behind FINAL BOSS, built from nothing. You'll learn what an ELF is, how to read disassembly without panicking, how to pull secrets statically (strings, `objdump`, decoding immediates), the single most powerful dynamic trick (breaking on the compare), and a repeatable method for "crack-me" style multi-stage binaries.

## How to read this

- **PART 0**, what a compiled program *is* (ELF, sections, symbols).
- **PART 1**, the one idea (static vs dynamic, and why dynamic usually wins).
- **PART 2**, the static toolkit.
- **PART 3**, reading enough assembly to win.
- **PART 4**, decoding embedded data (the XOR-key pattern).
- **PART 5**, the dynamic toolkit (gdb, break-on-compare).
- **PART 6**, a method for multi-stage crackmes.
- **PART 7**, defenses & where this matters.
- Glossary + next.

---

# PART 0, The Building Blocks

A compiled program is a file of machine code plus data, in a container format. On Linux that's **ELF**. The parts you care about:

- **sections**: `.text` (executable code), `.rodata` (read-only constants, strings, tables), `.data`/`.bss` (variables).
- **symbols**: names for functions/variables. If the binary is **not stripped**, you get real names like `stage2_cryptography`, a huge gift. `strip` removes them.
- **imports** (PLT/GOT): calls into libc (`printf`, `strcmp`, `fgets`, `system`).

`file ./bin` tells you arch/bitness/stripped. FINAL BOSS: *"ELF 64-bit x86-64, dynamically linked, not stripped"*, meaning readable names and standard libc calls.

---

# PART 1, The One Idea

> **A binary you can download is a binary you can read *and run*. Static analysis shows you what it *would* do; dynamic analysis shows you what it *does*, including any secret it computes at runtime.** When a program *compares* your input to a secret, you rarely need to understand the math: you watch the comparison.

---

# PART 2, The Static Toolkit

```bash
file ./bin                       # arch, bitness, stripped?
strings -n5 ./bin                # printable strings — prompts, hints, formats, maybe the flag
strings -t x ./bin               # with file offsets (to cross-ref .rodata)
nm ./bin | grep ' T '            # defined functions (if not stripped)
objdump -d -M intel ./bin        # full disassembly, Intel syntax
objdump -s -j .rodata ./bin      # hexdump of constants (strings, tables, keys)
readelf -a ./bin                 # headers, sections, symbols, relocations
```

For FINAL BOSS, `strings` alone revealed the stage structure, the stage-2 ciphertext, the hint strings, and `STAGE3_TOKEN`. **Always run `strings` first**, many crackmes are solved by it.

Nicer tools when available: **Ghidra** (free decompiler → C-ish pseudocode), **radare2/Cutter**, **IDA**. A decompiler turns Part 3 from "read asm" into "read code."

---

# PART 3, Reading Just Enough Assembly

You don't need to be fluent. Recognize a handful of patterns:

- `mov`, `lea`, move / load-address (load a pointer to a string/buffer).
- `movabs rax, 0x...`, load an 8-byte immediate (often **packed ASCII**, decode it!).
- `cmp` / `test` then `je`/`jne`, a comparison and conditional jump (a *check*, your input vs. something).
- `call <strcmp@plt>` / `call <printf@plt>`, libc calls; args in `rdi, rsi, rdx, rcx` (System V x86-64).
- `xor` in a loop, decoding/obfuscation.

The high-value targets are **`cmp`/`strcmp`/`strncmp` sites**, that's where "is the password right?" lives. Find those and you find the secret.

To isolate one function in `objdump`:

```bash
objdump -d -M intel ./bin | awk '/<stage2_cryptography>:/{f=1} f{print} /<stage3_exploitation>:/{if(f)exit}'
```

---

# PART 4, Decoding Embedded Data (the XOR-key pattern)

Crackmes love to store a secret *obfuscated* so `strings` won't reveal it, then de-obfuscate at runtime. FINAL BOSS's stage 1 is the canonical example:

- The disassembly loads 14 bytes via `movabs`/`mov` immediates onto the stack (little-endian).
- Nearby stack strings spell the algorithm: `XOR_KEY_IS_0x42`, `LOOP_COUNT_14_BYTES`, `OPERATION_XOR_EACH_BYTE`.
- So: `plaintext[i] = stored[i] ^ 0x42`.

Decoding immediates: a `movabs rax, 0x1d71313071347110` is 8 bytes **little-endian**, byte order is reversed from how it's written. In Python:

```python
import struct
b = struct.pack('<Q',0x1d71313071347110) + struct.pack('<I',0x3631760f) + struct.pack('<H',0x3071)
# '<Q'=8-byte, '<I'=4-byte, '<H'=2-byte, little-endian  → 14 bytes total
print(''.join(chr(c ^ 0x42) for c in b))     # R3v3rs3_M4st3r
```

General recipe for "find the key" stages:
1. Spot the stored constants (immediates or a `.rodata` blob).
2. Spot the transform (XOR/add/sub/rol in a loop) and its parameter(s).
3. Reproduce it in Python. Done.

If you can't see the transform clearly, skip to Part 5 and let the program apply it for you.

---

# PART 5, The Dynamic Toolkit (gdb), and the one trick that wins

Static reading is optional when you can run the binary and watch it. The highest-leverage move: **break on the comparison and read both operands.** The program has already computed the secret by then.

```bash
# find the compare
objdump -d -M intel ./bin | grep -n strcmp     # e.g. call at 0x401946

cat > cmds <<'EOF'
set pagination off
break *0x401946            # the strcmp site
run
printf "yours=%s\n",    (char*)$rdi    # arg1 (System V: rdi)
printf "expected=%s\n", (char*)$rsi    # arg2 (rsi) ← the secret
continue
EOF
printf 'stage1ans\nWHATEVER\n' | gdb -q -x cmds ./bin | grep -E 'yours|expected'
```

For FINAL BOSS stage 2 this printed `expected=Overflow_1s_P0w3rful`, the Caesar+Vigenère plaintext, **without reversing the cipher at all.** This trick beats most "enter the password/decrypt this" crackmes:

- Args are in `rdi, rsi, rdx, ...` (x86-64 System V). `strcmp(a,b)` → `a=rdi`, `b=rsi`.
- Works for `strcmp`, `strncmp`, `memcmp`, and manual `cmp` loops (break in the loop, inspect the register/memory being compared).
- If the check is inlined, break at the `cmp` and examine the compared bytes.

Other gdb essentials:
- `break *0xADDR` / `break func`, `run`, `continue`, `stepi`/`nexti`.
- `x/20xb $rsi`, `x/s $rsi`, examine memory as bytes/string.
- `info registers`.
- Feed stdin with a pipe or `run < input`. Patch past checks with `set $rip=`/`set var` if needed.
- **pwndbg/gef** make all of this far friendlier.

---

# PART 6, A Method for Multi-Stage Crackmes

1. `file` + `strings` + `nm` → map the stages and grab any free secrets.
2. For each stage, open its function in a decompiler (Ghidra) or `objdump`.
3. Classify the stage:
   - *"find the hidden key"* → decode embedded constants (Part 4).
   - *"enter the decryption / password"* → break on the compare (Part 5).
   - *"token/flag string"* → it's often just in `.rodata` (grep it).
   - *"exploit the overflow"* → sometimes the web/CTF wrapper just wants the token the overflow would reveal; check if the token is a plain string first (FINAL BOSS's stage-3 "exploitation" was satisfied by the `.rodata` token).
4. Mind the **harness state**: if a server/web layer gates stages, it tracks progress (here, a **session cookie**), submit in order, same session.

---

# PART 7, Defenses & Where This Matters

- **Don't ship secrets in client binaries/apps.** Reversers extract them (same lesson as VELVET ROOM's JS key, COMEBACK KIT's APK string). Validate server-side.
- **Compare hashes, not plaintext**, so a debugger on the compare sees only a digest.
- **Strip symbols**, add obfuscation/anti-debug, raises cost, never stops a determined analyst.
- Real-world relevance: license checks, DRM, malware analysis, firmware secret extraction, mobile app keys, game anti-cheat.

---

# Glossary

- **ELF**, Executable and Linkable Format; the Linux binary container.
- **`.text` / `.rodata`**, code / read-only constants (strings, keys, tables).
- **Stripped**, symbol names removed; harder to read.
- **Immediate**, a constant encoded directly in an instruction (often packed ASCII, little-endian).
- **PLT/GOT**, the mechanism for calling libc functions (`strcmp`, `system`).
- **System V ABI**, x86-64 calling convention: args in `rdi, rsi, rdx, rcx, r8, r9`.
- **Break-on-compare**, set a breakpoint at a `cmp`/`strcmp` and read the operands; the secret is right there.
- **Decompiler**, tool (Ghidra/IDA) that recovers C-like source from machine code.

# Where to Go Next

- Install **Ghidra** and redo FINAL BOSS from the decompiler view, see the XOR loop and the `strcmp` in pseudocode.
- Practice break-on-compare on any "enter the password" crackme (crackmes.one), it generalizes enormously.
- The CTF's **capture** guide (XOR keystream) pairs well, same XOR/known-plaintext muscle, applied to a packet capture instead of a binary.
