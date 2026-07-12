# Crypto Test GUI

Tool Python GUI de test nhanh cho firmware secureboot.

## Chay

```powershell
cd D:\Embedded\Project\stm32f103\secureboot
python script\crypto_test_gui.py
```

## Tinh nang

- SHA-256: nhap string UTF-8 hoac hex/C array, xuat digest dang hex va C hex array.
- AES-128 GCM: nhap plaintext string/hex, key 16 byte, nonce 12 byte, AAD tuy chon; xuat ciphertext, tag va `ciphertext || tag`.
- AES-128 GCM: co nut auto-generate key 16 byte va IV/nonce 12 byte ngau nhien.
- AES-128 GCM: decrypt bang `ciphertext || tag`, hoac ciphertext rieng kem tag 16 byte.
- ECDH X25519: nhap private/public key cua Alice va Bob, tinh shared key hai phia va so sanh.
- ECDH X25519: co nut auto-generate keypair cho Alice/Bob de copy vao firmware.
- ECDH X25519: co nut tinh public key tu private key.
- ECDSA P-256: nhap raw data string/hex, private key/public key P-256, sign va verify chu ky.
- ECDSA P-256: co nut tinh public key tu private key.
- ECDSA P-256: khi sign se xuat SHA-256 cua data input, chu ky DER va raw `r || s`; verify duoc ca hai dinh dang.

## Dependency

Tkinter va hashlib la thu vien co san cua Python. X25519/ECDSA can package:

```powershell
python -m pip install -r script\requirements.txt
```

May hien tai da co `cryptography`, nen co the chay truc tiep.
