# Secure Boot Flash Layout

This project targets the 64 KiB STM32F103C8T6 Flash. Every erase page is 1 KiB.

| Region | Address range | Size | Purpose |
| --- | --- | ---: | --- |
| Boot | `0x08000000` - `0x08009FFF` | 40 KiB | Secure bootloader |
| App1 | `0x0800A000` - `0x0800C7FF` | 10 KiB | Fixed runtime application slot |
| App2 | `0x0800C800` - `0x0800EFFF` | 10 KiB | Fixed FOTA staging slot |
| Data | `0x0800F000` - `0x0800FFFF` | 4 KiB | Boot state and future persistent data |

The application must link its vector table at APP1 (`0x0800A000`). During FOTA
the APP1-linked image is first written into APP2 as staging, then copied into
APP1 after verification. The last 256 bytes of each slot contain
`secure_boot_manifest_t`, so application code is limited to 9,984 bytes.

The manifest is signed as raw bytes from offset 0 through the byte before
`signature`; the signature format is ECDSA P-256 `r || s` (64 bytes), and the
signed digest is SHA-256. `image_sha256` is SHA-256 of exactly `image_size` bytes
starting at the stored image bytes. For APP2 staging, vector-table validation
still checks that the reset handler targets the APP1 runtime range.

The first two data Flash pages contain alternating status records. APP2 is always
the FOTA target and APP1 is always the boot target. `update_state=RECEIVING` is
written before erasing/writing APP2, and `update_state=COMMITTING` is written
after image verification but before APP2 manifest programming and APP2-to-APP1
publish. If reset or power loss occurs during `COMMITTING`, recovery verifies
the APP2 staging manifest and repeats the copy into APP1; if the staging
manifest is incomplete or invalid, recovery clears the marker and keeps using
the previous APP1 image. See the power-loss proof argument in `README.md` for
the reset-point case analysis.

Replace the all-zero public key in `Core/Src/secure_boot_public_key.c` with the
immutable production ECDSA P-256 public key before shipping. The default fails
closed and will intentionally reject every image. Production hardware also needs
an appropriate readout-protection and debug-port policy; Flash signatures alone
do not protect a device an attacker can reprogram through an unlocked debugger.
