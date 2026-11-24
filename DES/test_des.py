from des import des_encrypt, des_decrypt

plaintext = 0x0123456789ABCDEF
key = 0x133457799BBCDFF1
expected = 0x85E813540F0AB405

ciphertext = des_encrypt(plaintext, key, show=False)
decrypted = des_decrypt(ciphertext, key)

print("DES TEST VECTOR")
print(f"Plaintext : {plaintext:016X}")
print(f"Key       : {key:016X}")
print(f"Ciphertext: {ciphertext:016X}")
print(f"Decrypted : {decrypted:016X}")

assert ciphertext == expected
assert decrypted == plaintext

print("DES TEST PASSED!")