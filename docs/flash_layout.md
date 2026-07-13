# Secure Boot Flash Layout

This project targets the 64 KiB STM32F103C8T6 Flash. Every erase page is 1 KiB.

| Region | Address range | Size | Purpose |
| --- | --- | ---: | --- |
| Boot | `0x08000000` - `0x08009FFF` | 40 KiB | Secure bootloader |
| App1 | `0x0800A000` - `0x0800C7FF` | 10 KiB | Application slot 1 |
| App2 | `0x0800C800` - `0x0800EFFF` | 10 KiB | Application slot 2 |
| Data | `0x0800F000` - `0x0800FFFF` | 4 KiB | Boot state and future persistent data |

Each application must link its vector table at the beginning of its slot. The last
256 bytes of the slot contain `secure_boot_manifest_t`, so application code is
limited to 9,984 bytes.

The manifest is signed as raw bytes from offset 0 through the byte before
`signature`; the signature format is ECDSA P-256 `r || s` (64 bytes), and the
signed digest is SHA-256. `image_sha256` is SHA-256 of exactly `image_size` bytes
starting at the application vector table.

The first two data Flash pages contain alternating status records. A candidate
image is booted once after `secure_boot_request_trial()`. The candidate must call
`secure_boot_confirm_running_image()` after its self-test; otherwise the next
reset clears the trial and boots the last confirmed valid image.

Replace the all-zero public key in `Core/Src/secure_boot_public_key.c` with the
immutable production ECDSA P-256 public key before shipping. The default fails
closed and will intentionally reject every image. Production hardware also needs
an appropriate readout-protection and debug-port policy; Flash signatures alone
do not protect a device an attacker can reprogram through an unlocked debugger.
