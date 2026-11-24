
# AES-128 - Encryption and Decryption

# ===== CAC PHEP TOAN GF(2^8) =====

def gf_mul(a, b):
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return result


def gf_pow(a, power):
    result = 1
    while power:
        if power & 1:
            result = gf_mul(result, a)
        a = gf_mul(a, a)
        power >>= 1
    return result


def rotate_byte(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def make_sbox():
    box = []
    for x in range(256):
        inv = gf_pow(x, 254) if x else 0
        value = inv ^ rotate_byte(inv, 1) ^ rotate_byte(inv, 2) \
                ^ rotate_byte(inv, 3) ^ rotate_byte(inv, 4) ^ 0x63
        box.append(value)
    return box


SBOX = make_sbox()
INV_SBOX = [0] * 256

for i, value in enumerate(SBOX):
    INV_SBOX[value] = i


# ===== KEY EXPANSION =====

RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
]


def key_expansion(key):
    expanded = list(key)

    for i in range(4, 44):
        temp = expanded[(i - 1) * 4:i * 4]

        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[i // 4]

        for j in range(4):
            expanded.append(expanded[(i - 4) * 4 + j] ^ temp[j])

    return [
        expanded[i * 16:(i + 1) * 16]
        for i in range(11)
    ]


# ===== CAC PHEP BIEN DOI STATE =====

def add_round_key(state, round_key):
    return [a ^ b for a, b in zip(state, round_key)]


def sub_bytes(state):
    return [SBOX[b] for b in state]


def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]


def shift_rows(state):
    result = state[:]

    for r in range(4):
        for c in range(4):
            result[r + 4 * c] = state[r + 4 * ((c + r) % 4)]

    return result


def inv_shift_rows(state):
    result = state[:]

    for r in range(4):
        for c in range(4):
            result[r + 4 * c] = state[r + 4 * ((c - r) % 4)]

    return result


def mix_columns(state):
    result = state[:]

    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = state[i:i + 4]

        result[i]     = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3
        result[i + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3
        result[i + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3)
        result[i + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2)

    return result


def inv_mix_columns(state):
    result = state[:]

    for c in range(4):
        i = 4 * c
        a0, a1, a2, a3 = state[i:i + 4]

        result[i] = (
            gf_mul(a0, 14) ^ gf_mul(a1, 11) ^
            gf_mul(a2, 13) ^ gf_mul(a3, 9)
        )
        result[i + 1] = (
            gf_mul(a0, 9) ^ gf_mul(a1, 14) ^
            gf_mul(a2, 11) ^ gf_mul(a3, 13)
        )
        result[i + 2] = (
            gf_mul(a0, 13) ^ gf_mul(a1, 9) ^
            gf_mul(a2, 14) ^ gf_mul(a3, 11)
        )
        result[i + 3] = (
            gf_mul(a0, 11) ^ gf_mul(a1, 13) ^
            gf_mul(a2, 9) ^ gf_mul(a3, 14)
        )

    return result


def print_state(label, state):
    print(f"{label}: {bytes(state).hex().upper()}")


# ===== AES ENCRYPTION =====

def aes_encrypt(plaintext, key, show=True):
    round_keys = key_expansion(key)
    state = list(plaintext)

    state = add_round_key(state, round_keys[0])

    if show:
        print_state("Round 0 - AddRoundKey", state)

    for rnd in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])

        if show:
            print_state(f"Round {rnd} - Output", state)

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    if show:
        print_state("Round 10 - Output", state)

    return bytes(state)


# ===== AES DECRYPTION =====

def aes_decrypt(ciphertext, key, show=True):
    round_keys = key_expansion(key)
    state = list(ciphertext)

    state = add_round_key(state, round_keys[10])

    if show:
        print_state("Decrypt Round 10 - AddRoundKey", state)

    for rnd in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)

        if show:
            print_state(f"Decrypt Round {rnd} - Output", state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])

    if show:
        print_state("Decrypt Round 0 - Output", state)

    return bytes(state)


# ===== TEST VECTOR AES-128 =====

if __name__ == "__main__":

    plaintext = bytes.fromhex(
        "00112233445566778899AABBCCDDEEFF"
    )

    key = bytes.fromhex(
        "000102030405060708090A0B0C0D0E0F"
    )

    expected = (
        "69C4E0D86A7B0430D8CDB78070B4C55A"
    )

    print("========== AES-128 ENCRYPTION ==========")

    ciphertext = aes_encrypt(plaintext, key)

    print("\nPlaintext :", plaintext.hex().upper())
    print("Key       :", key.hex().upper())
    print("Ciphertext:", ciphertext.hex().upper())

    print("\n========== AES-128 DECRYPTION ==========")

    decrypted = aes_decrypt(ciphertext, key)

    print("\nDecrypted :", decrypted.hex().upper())

    assert ciphertext.hex().upper() == expected
    assert decrypted == plaintext

    print("\nAES-128 TEST PASSED!")
