# Crypto Test GUI

Python GUI tools for testing secure boot cryptography and UART FOTA flows.

## Run

```powershell
cd D:\Embedded\Project\stm32f103\secure_boot
python script\crypto_test_gui.py
```

## Features

- SHA-256: enter UTF-8 text or hex/C array data, output digest as hex and C
  array.
- AES-128 GCM: encrypt/decrypt using a 16-byte key, 12-byte nonce, and optional
  AAD.
- AES-128 GCM: auto-generate key and IV/nonce.
- AES-128 GCM: decrypt either `ciphertext || tag` or ciphertext plus a separate
  16-byte tag.
- ECDH X25519: enter Alice/Bob private and public keys, compute and compare
  shared keys.
- ECDH X25519: auto-generate key pairs and derive public key from private key.
- ECDSA P-256: sign and verify raw data.
- ECDSA P-256: derive public key from private key.
- ECDSA P-256: signing outputs SHA-256, DER signature, and raw `r || s`
  signature; verification accepts both DER and raw forms.

## Dependency

Tkinter and hashlib are included with Python. X25519/ECDSA and UART FOTA need
external packages:

```powershell
python -m pip install -r script\requirements.txt
```

## UART FOTA tool

Run GUI:

```powershell
python script\fota_uart_tool.py
```

Generate key/cert/public-key C array:

```powershell
python script\fota_uart_tool.py gen-key --out-dir script\keys
```

Sign firmware and export metadata:

```powershell
python script\fota_uart_tool.py sign --firmware app.bin --key script\keys\secure_boot_p256_private_key.pem --version 1 --out app.fota.json
```

The UART tool uses the bootloader protocol:

- `UPDATE_BEGIN`: slot, image size, version, firmware SHA-256, raw ECDSA P-256
  signature `r || s`.
- `UPDATE_CHUNK`: offset plus data, default 200 bytes per chunk.
- `UPDATE_END`: request bootloader verification and trial boot setup.
- `VERIFY_SLOT`, `BOOT_NOW`, and `STATUS` for debug.

`Reset/wait boot` can reset the target automatically only when USB-UART DTR/RTS
is wired to the target reset/boot circuitry. Otherwise, reset the MCU manually
and let the tool wait for the `BOOT` report.
