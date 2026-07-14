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

Sign both APP1/APP2 firmware binaries from a folder and export metadata:

```powershell
python script\fota_uart_tool.py sign-folder --firmware-dir path\to\folder_with_app1_app2_bins --key script\keys\secure_boot_p256_private_key.pem --version 1 --out firmware_bundle.fota.json
```

The UART tool uses the bootloader protocol:

- `UPDATE_BEGIN`: image size, version, firmware SHA-256, raw ECDSA P-256
  signature `r || s`.
- `UPDATE_CHUNK`: offset and data, default 200 bytes per chunk. The first
  chunk must contain at least the first 8 firmware bytes.
- `UPDATE_END`: requests bootloader verification and trial boot setup.
- `RESET`: request a fresh bootloader session before update.
- `SLOT_INFO`: query APP1/APP2 metadata and the bootloader-selected target slot
  so the host can choose the matching binary.

Click `Start update` to send `RESET`, wait for the periodic `BOOT` status
report, query `SLOT_INFO`, and transfer the signed firmware linked for the
target slot. The PC tool does not send the slot; the bootloader selects the
inactive slot from persistent boot status and validates that the first chunk
vector table was linked for that selected slot.
If the application does not handle `RESET` and USB-UART DTR/RTS is not wired to
the target reset/boot circuitry, reset the MCU manually after clicking
`Start update`.

Update communication flow:

1. Tool signs both APP1-linked and APP2-linked `.bin` files from the selected
   folder.
2. Tool sends `RESET`, or user manually resets the MCU when reset wiring is not
   available.
3. Firmware enters bootloader mode and sends `BOOT`.
4. Tool waits for `BOOT`, then sends `SLOT_INFO`.
5. Firmware returns APP1/APP2 metadata plus `target_update_slot`.
6. Tool chooses the signed binary matching `target_update_slot`.
7. Tool sends `UPDATE_BEGIN(size, version, sha256, signature)`.
8. Firmware selects the update slot internally again and replies
   `ACK UPDATE_BEGIN`.
9. Tool streams `UPDATE_CHUNK` frames.
10. Firmware validates the first chunk vector table against its selected slot,
    writes accepted chunks to Flash, and ACKs each chunk.
11. Tool sends `UPDATE_END`.
12. Firmware verifies hash/signature, writes the manifest, marks the image as
    trial, replies `ACK UPDATE_END`, sends `JUMP`, and boots the trial image.
