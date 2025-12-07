
# Time‑Delayed Password (Obfuscated, Not Encrypted)

Obfuscated time‑delayed password reveal. Useful for self‑imposed limits (personal lockouts, “don’t let me peek yet” challenges). Designed to delay access, not to provide real security.

## What this is
- Obfuscated time‑gated password tool
- Useful for self‑imposed limits and challenges
- Works offline; no external servers
- Simple CLI; minimal dependencies
- Single‑binary builds via Nuitka
- Requires native libraries (.so/.dll/.dylib) for operation

## What this is not
- Not encrypted storage
- Not resistant to determined reverse engineering
- Not suitable for high‑value or sensitive secrets
- Not a replacement for proper cryptography or key management

## Required native components
This project requires the native C libraries. They are not optional.

- Required files (Linux example):
  - libsecure_aes.so
  - second_encrypt.so
- Windows: use .dll
- macOS: use .dylib
- Place the compiled libraries next to main.py before building.
- They must also be bundled into the final binary (see build commands below).

## Important: Update keys in C code before building
Before compiling the shared libraries:
- Edit the C source to change any hard‑coded keys, IVs, salts, or constants.
- Do not ship default/example keys.
- Do not embed real secrets you care about; with enough effort, they can be extracted.

Example placeholders to update in C:
- const uint8_t AES_KEY[32] = { /* your 32 bytes */ };
- const uint8_t AES_IV[16]  = { /* your 16 bytes */ };

Rebuild the shared libraries after edits, then build the Python executable.

## Features
- Configurable delay or absolute unlock time
- Persistence option so timers survive restarts
- Single‑binary builds via Nuitka (onefile/standalone)
- Required C‑backed routines for core functionality
- Cross‑platform friendly (build on the target OS/arch)

## Quick start
Prerequisites:
- Python 3.8–3.12
- C/C++ toolchain:
  - Linux: gcc/clang and build‑essentials
  - macOS: Xcode Command Line Tools
  - Windows: MSVC Build Tools
- Python packages:
  - python -m pip install nuitka ordered-set zstandard

1) Build the required native libraries from your C source and place the .so/.dll/.dylib files next to main.py.
2) Run from source to verify:
```bash
python main.py
```

## Build a single binary (Nuitka)
Linux/macOS (two required libraries):
```bash
python -m pip install --upgrade nuitka ordered-set zstandard

python -m nuitka \
  --onefile --standalone --follow-imports --remove-output \
  --include-data-file="$(pwd)/libsecure_aes.so=libsecure_aes.so" \
  --include-data-file="$(pwd)/second_encrypt.so=second_encrypt.so" \
  main.py
```

Windows (PowerShell):
```powershell
py -m pip install --upgrade nuitka ordered-set zstandard

py -m nuitka `
  --onefile --standalone --follow-imports --remove-output `
  --include-data-file="$pwd\libsecure_aes.dll=libsecure_aes.dll" `
  --include-data-file="$pwd\second_encrypt.dll=second_encrypt.dll" `
  main.py
```

macOS:
```bash
python -m nuitka \
  --onefile --standalone --follow-imports --remove-output \
  --include-data-file="$(pwd)/libsecure_aes.dylib=libsecure_aes.dylib" \
  --include-data-file="$(pwd)/second_encrypt.dylib=second_encrypt.dylib" \
  main.py
```

Build tips:
- Add --lto=yes for link‑time optimization
- Add --clang on Linux/macOS to use Clang
- Use --onefile-no-compression for faster startup (larger binary)
- Always build on the same OS/architecture you will run on

## Loading the bundled libraries at runtime
Use this in your Python code so the binary can find the required libraries in onefile mode:

```python
import os
import sys
import ctypes as ct

def bundled_path(name: str) -> str:
    try:
        from nuitka.__past__ import getResourceDir
        return os.path.join(getResourceDir(), name)
    except Exception:
        pass
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, name)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name)

def load_libsecure_aes() -> ct.CDLL:
    p = bundled_path("libsecure_aes.so")  # .dll on Windows, .dylib on macOS
    if not os.path.exists(p):
        raise FileNotFoundError(f"Missing required shared library: {p}")
    lib = ct.CDLL(p)
    u8p = ct.POINTER(ct.c_uint8)
    lib.aes256cbc_encrypt.argtypes = [u8p, ct.c_int, u8p]
    lib.aes256cbc_encrypt.restype  = ct.c_int
    lib.aes256cbc_decrypt.argtypes = [u8p, ct.c_int, u8p]
    lib.aes256cbc_decrypt.restype  = ct.c_int
    return lib

def load_second_encrypt() -> ct.CDLL:
    p = bundled_path("second_encrypt.so")
    if not os.path.exists(p):
        raise FileNotFoundError(f"Missing required shared library: {p}")
    return ct.CDLL(p)
```

## Usage example
```bash
# Run from source
python main.py --delay 10m --secret-file secret.txt

# Or run the built binary
./main --delay 10m --secret-file secret.txt
```

```text
Options (example):
  --delay 10m | 2h | 1d      Delay before reveal
  --at 2025-12-31T23:59:00Z  Reveal at absolute time (UTC ISO-8601)
  --secret-file path         File containing the secret/password
  --state-dir path           Persistence so timers survive restarts
```

## Disclaimer
- This project delays and obfuscates; it does not provide cryptographic protection.
- Do not store sensitive or high‑value secrets.
- The required C libraries must be present and will be bundled into the final binary.

## License
MIT 
