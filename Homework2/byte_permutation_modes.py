from __future__ import annotations
import sys

# Block size in bytes
BLOCK_SIZE = 16

# Permutation of indices {0..15}: ciphertext byte i comes from plaintext byte perm[i].
# Chosen as a non-trivial derangement (single cycle of length 16).
PERM = [1, 3, 5, 7, 9, 11, 13, 15, 0, 2, 4, 6, 8, 10, 12, 14]

# Inverse: pt[j] = ct[inv_perm[j]]  <=>  ct[i] = pt[perm[i]]  with inv_perm[perm[i]] = i
INV_PERM = [0] * BLOCK_SIZE
for i, j in enumerate(PERM):
    INV_PERM[j] = i

def encrypt_block(block: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"block must be {BLOCK_SIZE} bytes")
    return bytes(block[PERM[i]] for i in range(BLOCK_SIZE))

def decrypt_block(block: bytes) -> bytes:
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"block must be {BLOCK_SIZE} bytes")
    return bytes(block[INV_PERM[j]] for j in range(BLOCK_SIZE))

def xor_blocks(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _hx(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def _row(label: str, value: str, indent: int = 0, width: int = 20) -> None:
    print(f"{' ' * indent}{label:<{width}}: {value}")


# --- PKCS#7 padding (plaintext in CBC / CFB / OFB before XOR chaining) ---

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid PKCS#7 padding")
    return data[:-pad_len]


# --- CBC ---

def cbc_encrypt(plaintext: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must match block size")
    pt = pkcs7_pad(plaintext)
    out = bytearray()
    prev = iv
    for i in range(0, len(pt), BLOCK_SIZE):
        block = pt[i : i + BLOCK_SIZE]
        x = xor_blocks(block, prev)
        c = encrypt_block(x)
        out.extend(c)
        prev = c
    return bytes(out)

def cbc_decrypt(ciphertext: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must match block size")
    if not ciphertext or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a positive multiple of block size")
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        c = ciphertext[i : i + BLOCK_SIZE]
        x = decrypt_block(c)
        p = xor_blocks(x, prev)
        out.extend(p)
        prev = c
    return pkcs7_unpad(bytes(out))


# --- CFB (full-block feedback; plaintext padded with PKCS#7 so all blocks are full) ---

def cfb_encrypt(plaintext: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must match block size")
    pt = pkcs7_pad(plaintext)
    out = bytearray()
    shift = iv
    for i in range(0, len(pt), BLOCK_SIZE):
        block = pt[i : i + BLOCK_SIZE]
        o = encrypt_block(shift)
        c = xor_blocks(block, o)
        out.extend(c)
        shift = c
    return bytes(out)

def cfb_decrypt(ciphertext: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must match block size")
    if not ciphertext or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a positive multiple of block size")
    out = bytearray()
    shift = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        c = ciphertext[i : i + BLOCK_SIZE]
        o = encrypt_block(shift)
        p = xor_blocks(c, o)
        out.extend(p)
        shift = c
    return pkcs7_unpad(bytes(out))


# --- OFB (keystream from encrypting the chaining value; same keystream for enc/dec) ---

def ofb_encrypt(plaintext: bytes, iv: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must match block size")
    pt = pkcs7_pad(plaintext)
    out = bytearray()
    chain = iv
    for i in range(0, len(pt), BLOCK_SIZE):
        block = pt[i : i + BLOCK_SIZE]
        o = encrypt_block(chain)
        c = xor_blocks(block, o)
        out.extend(c)
        chain = o
    return bytes(out)

def ofb_decrypt(ciphertext: bytes, iv: bytes) -> bytes:
    # Identical to encryption (XOR with the same keystream)
    if len(iv) != BLOCK_SIZE:
        raise ValueError("IV must match block size")
    if not ciphertext or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a positive multiple of block size")
    out = bytearray()
    chain = iv
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        c = ciphertext[i : i + BLOCK_SIZE]
        o = encrypt_block(chain)
        p = xor_blocks(c, o)
        out.extend(p)
        chain = o
    return pkcs7_unpad(bytes(out))


def demo_cbc(iv: bytes) -> None:
    """Flow-only CBC trace with intermediate values."""
    plaintext = "Merhaba dunya".encode("utf-8")
    pt = pkcs7_pad(plaintext)
    print("\n=== CBC (Cipher Block Chaining) ===\n")
    _row("IV / C_0", _hx(iv))
    _row("Plaintext bytes", repr(plaintext))
    _row("Padded P'", _hx(pt))
    print()

    prev = iv
    for bi in range(0, len(pt), BLOCK_SIZE):
        block = pt[bi : bi + BLOCK_SIZE]
        x = xor_blocks(block, prev)
        c = encrypt_block(x)
        n = bi // BLOCK_SIZE + 1
        print(f"Block {n}:")
        _row(f"C_{n-1}", _hx(prev), indent=2)
        _row(f"P'_{n}", _hx(block), indent=2)
        _row(f"X_{n}=P'_{n}^C_{n-1}", _hx(x), indent=2)
        _row(f"C_{n}=E(X_{n})", _hx(c), indent=2)
        prev = c

    ct = cbc_encrypt(plaintext, iv)
    print()
    _row("Ciphertext (hex)", ct.hex())
    dec = cbc_decrypt(ct, iv)
    _row("Recovered", f"{dec!r}  (match: {dec == plaintext})")
    print()


def demo_cfb(iv: bytes) -> None:
    """Flow-only CFB trace with intermediate values."""
    plaintext = "Merhaba dunya".encode("utf-8")
    pt = pkcs7_pad(plaintext)
    print("\n=== CFB (Cipher Feedback) ===\n")
    _row("Initial S_0", _hx(iv))
    _row("Plaintext bytes", repr(plaintext))
    _row("Padded P'", _hx(pt))
    print()

    shift = iv
    for bi in range(0, len(pt), BLOCK_SIZE):
        block = pt[bi : bi + BLOCK_SIZE]
        o = encrypt_block(shift)
        c = xor_blocks(block, o)
        n = bi // BLOCK_SIZE + 1
        print(f"Block {n}:")
        _row(f"S_{n-1}", _hx(shift), indent=2)
        _row(f"O_{n}=E(S_{n-1})", _hx(o), indent=2)
        _row(f"P'_{n}", _hx(block), indent=2)
        _row(f"C_{n}=P'_{n}^O_{n}", _hx(c), indent=2)
        _row(f"S_{n}", f"C_{n}", indent=2)
        shift = c

    ct = cfb_encrypt(plaintext, iv)
    print()
    _row("Ciphertext (hex)", ct.hex())
    dec = cfb_decrypt(ct, iv)
    _row("Recovered", f"{dec!r}  (match: {dec == plaintext})")
    print()


def demo_ofb(iv: bytes) -> None:
    """Flow-only OFB trace with intermediate values."""
    plaintext = "Merhaba dunya".encode("utf-8")
    print("\n=== OFB (Output Feedback) ===\n")
    shift = iv
    pt = pkcs7_pad(plaintext)
    _row("Initial S_0", _hx(iv))
    _row("Plaintext bytes", repr(plaintext))
    _row("Padded P'", _hx(pt))
    print()

    for bi in range(0, len(pt), BLOCK_SIZE):
        block = pt[bi : bi + BLOCK_SIZE]
        o = encrypt_block(shift)
        n = bi // BLOCK_SIZE + 1
        c = xor_blocks(block, o)
        print(f"Block {n}:")
        _row(f"S_{n-1}", _hx(shift), indent=2)
        _row(f"O_{n}=E(S_{n-1})", _hx(o), indent=2)
        _row(f"P'_{n}", _hx(block), indent=2)
        _row(f"C_{n}=P'_{n}^O_{n}", _hx(c), indent=2)
        _row(f"S_{n}", f"O_{n}", indent=2)
        shift = o

    ct = ofb_encrypt(plaintext, iv)
    print()
    _row("Ciphertext (hex)", ct.hex())
    dec = ofb_decrypt(ct, iv)
    _row("Recovered", f"{dec!r}  (match: {dec == plaintext})")
    print()


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    iv = bytes(range(16))

    if "--no-demo" not in sys.argv:
        demo_cbc(iv)
        demo_cfb(iv)
        demo_ofb(iv)

    msg = b"Hello, CBC/CFB/OFB with a byte permutation cipher."

    assert cbc_decrypt(cbc_encrypt(msg, iv), iv) == msg
    assert cfb_decrypt(cfb_encrypt(msg, iv), iv) == msg
    assert ofb_decrypt(ofb_encrypt(msg, iv), iv) == msg

    print("All round-trip checks passed.")