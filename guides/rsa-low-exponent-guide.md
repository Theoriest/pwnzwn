# Masterclass: Low-Exponent RSA, Cube Roots & Håstad's Broadcast, From Zero

The bug behind THREE ENCORES. By the end you'll understand just enough RSA to spot when `e=3` makes it fall apart, how to recover plaintext with a plain cube root or a broadcast (Håstad) attack, how to tell which case you're in, and how padding fixes all of it.

## How to read this

- **PART 0**, RSA in four lines.
- **PART 1**, the one idea.
- **PART 2**, case A: un-reduced cube (`m³ < n`).
- **PART 3**, case B: Håstad broadcast (same `m`, several `n`).
- **PART 4**, telling the cases apart, and other low-`e` attacks.
- **PART 5**, fixes.
- Glossary + next.

---

# PART 0, RSA in Four Lines

- **Public key:** a modulus `n` (product of two big primes) and an exponent `e` (commonly 65537; sometimes 3).
- **Encrypt:** `c = m^e mod n`, where `m` is the message as an integer.
- **Decrypt:** `m = c^d mod n`, where `d` is the private exponent (needs the factorization of `n`).
- **Security rests on** `n` being hard to factor, *and* on `m` being properly padded so it's a big, random-looking number.

"Textbook RSA" (no padding) breaks that last assumption, and a small `e` turns the break into a one-liner.

---

# PART 1, The One Idea

> **With `e=3`, if the padded message isn't big enough, `m³` stays small compared to the modulus (or compared to the product of several moduli), and a cube root, plain or via CRT, hands you `m`.** No factoring required.

THE THREE ENCORES case was the simplest flavour: `m³` never even reached one modulus, so `c` was literally `m³` and a single integer cube root solved it.

---

# PART 2, Case A: The Un-reduced Cube (`m³ < n`)

If the message is short and unpadded, `m³ < n`, so `c = m³ mod n = m³`, the modulus never bites. The ciphertext is a perfect cube and you just invert it:

```python
def icbrt(n):                       # integer cube root (binary search)
    lo,hi=0,1<<((n.bit_length()//3)+2)
    while lo<hi:
        mid=(lo+hi)//2
        if mid**3<n: lo=mid+1
        else: hi=mid
    return lo

c = int(c_hex,16)
m = icbrt(c)
assert m**3 == c                    # exact ⇒ it really was un-reduced
msg = m.to_bytes((m.bit_length()+7)//8,'big')
```

**The tell in THREE ENCORES:** the same `c` appeared under three *different* `n`. That can only happen if no reduction occurred (the operation `m³ mod n` ignored `n`), i.e. `c = m³`. `assert m**3==c` confirms it.

---

# PART 3, Case B: Håstad's Broadcast Attack

Now the "proper" version the challenge was hinting at. If the *same* message `m` is sent to **`e` recipients** with exponent `e` and different moduli `n1…ne`, you get:

```
c1 = m^3 mod n1 ,  c2 = m^3 mod n2 ,  c3 = m^3 mod n3
```

By CRT, there's a unique `X < n1·n2·n3` with `X ≡ ci (mod ni)`. Since `m < ni` for all, `m³ < n1·n2·n3`, so `X = m³` exactly. Then cube-root `X`:

```python
from sympy.ntheory.modular import crt
X,_ = crt(ns, cs)          # X = m^3  (mod ∏ ni)
m = icbrt(int(X))
assert m**3 == int(X)
```

You need as many ciphertexts as the exponent (`e=3` → 3). In THREE ENCORES the three `c` were identical, so CRT collapses to `c` itself and you're back to Case A, but the shape (several `n`, small `e`, same `m`) is exactly what should make you reach for Håstad.

---

# PART 4, Telling Cases Apart & Other Low-`e` Attacks

- **Perfect cube?** Cube-root `c`; if `m**3==c`, done (Case A).
- **Several recipients, same `m`, `e` ciphertexts?** Håstad via CRT (Case B).
- **Same `n`, two `e` that are coprime, same `m`?** **Common-modulus** attack (combine with Bézout).
- **Two messages with a known linear relation, same `n`, small `e`?** **Franklin-Reiter** / coppersmith short-pad.
- **Small `d`?** Wiener's attack.
- **`n` shares a factor with another `n`, or primes are close?** GCD / Fermat factoring.

For anything non-trivial, `RsaCtfTool` and SageMath (Coppersmith, `small_roots`) automate the heavy cases, but recognizing *which* attack applies is the skill; the cube-root/Håstad pair is by far the most common in intro challenges.

---

# PART 5, The Fixes

1. **Always pad** with **OAEP** (`RSA/ECB/OAEPWithSHA-256`). Padding makes `m` a large, randomized number so `m^e` is always `> n`, and makes two encryptions of the same plaintext differ, killing both Case A and Håstad.
2. **Use `e = 65537`.** There's no real performance reason to use `e=3` today, and it removes the small-exponent footguns.
3. **Never broadcast the same unpadded plaintext** to multiple keys.
4. **Don't roll your own RSA.** Use a vetted library's high-level encrypt (which pads by default); "textbook" RSA is a teaching tool, not a cipher.

---

# Glossary

- **`n`, `e`, `d`**, RSA modulus, public exponent, private exponent.
- **Textbook / raw RSA**, RSA with no padding; insecure.
- **OAEP**, the standard randomized RSA padding; the fix.
- **Un-reduced cube**, `e=3` with `m³ < n`, so `c = m³` and a cube root recovers `m`.
- **Håstad's broadcast**, same `m` to `e` recipients with exponent `e`; CRT + cube root.
- **CRT**, Chinese Remainder Theorem; combines residues under coprime moduli.
- **Integer cube root**, exact `⌊c^(1/3)⌋`; check `r**3==c` for exactness.

# Where to Go Next

- Encrypt a short string with `e=3` and a big `n` (no padding), confirm `c` is a perfect cube, and cube-root it back. Then do it to 3 keys and solve with CRT (Håstad).
- Related in this dojo: **finalboss** and **capture** (the other crypto-flavoured solves) and **velvetroom** (AES with a leaked key), different primitives, same theme of "the crypto was used wrong, not broken."
