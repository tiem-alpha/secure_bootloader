# Repository Guidelines

## Project Structure & Module Organization

This repository contains an STM32F103 secure bootloader with UART FOTA support. Core firmware code lives under `Core/Src` and public headers under `Core/Inc`. Important modules include `Core/Src/boot_controller.c` for the update state machine, `Core/Src/secure_boot.c` for slot validation and boot policy, `Core/Src/flash` for Flash writes, `Core/Src/com` for UART framing, and `Core/Src/secure` for cryptographic primitives. STM32 HAL and generated startup files are in `Drivers`, `startup_stm32f103xb.s`, and CubeMX-generated support files. Host-side tools and keys live in `script`; protocol and layout notes live in `README.md` and `docs/flash_layout.md`.

## Build, Test, and Development Commands

- `cmake --preset Debug`: configure the Ninja build with the ARM GCC toolchain.
- `cmake --build --preset Debug`: build the bootloader from `build/Debug`.
- `ninja -C build/Debug`: rebuild after configuration.
- `python -m pip install -r script/requirements.txt`: install host tool dependencies.
- `python script/fota_uart_tool.py`: launch the UART FOTA GUI.
- `python script/crypto_test_gui.py`: launch crypto helper tests/tools.
- `python -m py_compile script/fota_uart_tool.py script/crypto_test_gui.py`: quick Python syntax check.

## Coding Style & Naming Conventions

C code uses `.clang-format` with LLVM base style, 4-space indentation, no tabs, 100-column limit, Allman braces, right-aligned pointers, and unsorted includes. Keep module APIs documented in headers with concise Doxygen comments. Use `snake_case` for functions and variables, uppercase macros, and module prefixes such as `boot_controller_`, `secure_boot_`, `boot_flash_`, and `boot_uart_`. Prefer small platform wrappers for HAL dependencies so boot policy remains portable.

## Testing Guidelines

There is no full automated firmware test suite in-tree. Agents should not run firmware builds unless explicitly requested by the user. When requested, run a Debug build and exercise the affected UART/FOTA path on hardware where possible. For Python tools, run `py_compile` only when requested or when directly relevant. Crypto or protocol changes should include deterministic known-vector checks when practical.

## Commit & Pull Request Guidelines

Recent commits use short imperative messages, for example `add api documentation` or `modify partition`. Keep commits focused and mention the affected module when useful. Pull requests should include a short problem summary, key implementation notes, build/test evidence, hardware validation status if applicable, and any Flash layout or protocol compatibility impact.

## Security & Configuration Tips

Do not commit production private keys. Files under `script` may contain development keys only. Keep public-key provisioning, anti-rollback behavior, and Flash layout changes explicit in reviews because they affect device recoverability.
