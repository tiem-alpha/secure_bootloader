# Test README

This document describes the current test utilities in the secureboot project.

## 1. SHA-256 Host Test

Test file: `test_sha256_host.c`

Purpose:

- Validate the SHA-256 implementation in `Core/Src/sha256.c`.
- Compare the result with standard test vectors:
  - empty input
  - `"abc"`
  - a 56-byte long message
  - chunked update using small input fragments

### Build

Run from the project root:

```powershell
gcc -std=c99 -Wall -Wextra -Werror -ICore\Inc Core\Src\sha256.c Core\Src\crypto_util.c test_sha256_host.c -o test_sha256_host.exe
```

`Core/Src/crypto_util.c` is required because `sha256.c` calls `crypto_secure_zero()` to clear the SHA-256 context after finalization.

### Run

```powershell
.\test_sha256_host.exe
```

Expected output:

```text
sha256 host vectors PASS
```

If a test fails, the program prints the failed case name, the expected digest, and the actual digest.

## 2. Crypto Test GUI

Main file: `script/crypto_test_gui.py`

Separate README: `script/README.md`

This tool is used to generate test vectors and quickly cross-check crypto primitives while testing the firmware.

### Install Dependencies

```powershell
python -m pip install -r script\requirements.txt
```

External dependency:

- `cryptography`

### Run The GUI

```powershell
python script\crypto_test_gui.py
```

### Features

- SHA-256: compute a digest from a UTF-8 string or hex/C array input.
- AES-128 GCM: encrypt/decrypt, auto-generate a 16-byte key and 12-byte nonce.
- ECDH X25519: generate key pairs, derive a public key from a private key, and compare Alice/Bob shared keys.
- ECDSA P-256: generate keys, sign, verify, and export signatures as DER or raw `r || s`.

## 3. Recommended Test Flow

When changing crypto code:

1. Build and run the SHA-256 host test.
2. Use the Crypto Test GUI to generate input/output vectors for the related primitive.
3. Copy C array vectors into firmware tests or compare them with firmware logs.
4. When adding a new primitive, add a dedicated host test following the style of `test_sha256_host.c`.

## 4. Generated Files

`test_sha256_host.exe` is the binary generated from the host test. It can be deleted and rebuilt at any time using the build command above.
