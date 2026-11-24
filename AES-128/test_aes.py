from aes import aes_encrypt, aes_decrypt

plaintext = bytes.fromhex(
    "00112233445566778899AABBCCDDEEFF"
)

key = bytes.fromhex(
    "000102030405060708090A0B0C0D0E0F"
)

expected = bytes.fromhex(
    "69C4E0D86A7B0430D8CDB78070B4C55A"
)

ciphertext = aes_encrypt(plaintext, key, show=False)
decrypted = aes_decrypt(ciphertext, key, show=False)

print("AES-128 TEST VECTOR")
print("Plaintext :", plaintext.hex().upper())
print("Key       :", key.hex().upper())
print("Ciphertext:", ciphertext.hex().upper())
print("Decrypted :", decrypted.hex().upper())

assert ciphertext == expected
assert decrypted == plaintext

print("AES-128 TEST PASSED!")