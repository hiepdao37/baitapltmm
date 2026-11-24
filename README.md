# BÀI TẬP LÍ THUYẾT MẬT MÃ

## 1. Giới thiệu
Project thực hiện cài đặt hai thuật toán mã hóa đối xứng:
- DES (Data Encryption Standard).
- AES-128 (Advanced Encryption Standard).

## 2. Công nghệ
- Ngôn ngữ lập trình: Python 3.
- Môi trường: Ubuntu.
- Công cụ: Visual Studio Code.

## 3. Cấu trúc project
- `DES/`: Mã nguồn và kiểm thử DES.
- `AES-128/`: Mã nguồn và kiểm thử AES-128.
- `Results/`: Kết quả thực thi và kiểm định.

## 4. Cách chạy

### DES
```bash
python3 DES/des.py
python3 DES/test_des.py
```

### AES-128
```bash
python3 AES-128/aes.py
python3 AES-128/test_aes.py
```

## 5. Kết quả kiểm định

**DES**
- Plaintext: `0123456789ABCDEF`
- Key: `133457799BBCDFF1`
- Ciphertext: `85E813540F0AB405`
- Trạng thái: PASSED

**AES-128**
- Plaintext: `00112233445566778899AABBCCDDEEFF`
- Key: `000102030405060708090A0B0C0D0E0F`
- Ciphertext: `69C4E0D86A7B0430D8CDB78070B4C55A`
- Trạng thái: PASSED

## 6. Kết luận
Hai thuật toán DES và AES-128 đã được cài đặt, kiểm thử mã hóa và giải mã thành công bằng Test Vector chuẩn.
