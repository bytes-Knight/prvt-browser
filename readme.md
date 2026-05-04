# Secure Brave Launcher (PySide6)

Password-protected launcher for the real Brave browser on Windows, with encrypted local profile storage.

## Features

- Startup authentication before browser UI appears
- First-run master password setup
- bcrypt password hashing + salted PBKDF2 key derivation
- Encrypted browser profile at rest (`profile.enc`)
- Lock browser button (re-lock without closing process)
- 5-attempt login lockout per run
- Launches installed `brave.exe` with a protected `--user-data-dir`
- Uses a private Brave profile only (separate from your regular Brave profile)
- Can run alongside your regular Brave browser without touching its profile
- Full Brave/Chromium extension compatibility (native Brave extension system)
- Native Brave tabs/session/extensions/history behavior
- Settings panel:
  - change password
  - homepage
  - Brave executable path
  - clear data
  - open extensions page (`brave://extensions`)
  - open bookmarks manager (`brave://bookmarks`)
- Security hardening:
  - no plaintext credential storage
  - remote debugging flags removed
  - profile encrypted when locked/closed
  - single-instance lock
  - process isolation: only manages Brave instances started with this app's private profile
- Bonus:
  - idle auto-lock timer (when unlocked and Brave is not running)
  - minimize-to-tray + tray menu lock/unlock
  - best-effort profile permission hardening

## Project Layout

```
auth.py         # Login + first-run password dialogs
encryption.py   # Password hashing, key derivation, profile encryption/decryption
settings.py     # App state store and settings dialog
main.py         # Auth + encrypted profile + Brave process lifecycle + tray controls
requirements.txt
readme.md
```

## Security Model

1. Password storage
- Master password is never stored.
- Stored value is `bcrypt` hash (`app_state.json`), which includes per-hash salt.

2. Encryption key derivation
- Separate random KDF salt is generated on setup and stored in `app_state.json`.
- Runtime key is derived with `PBKDF2-HMAC-SHA256` (390,000 iterations).

3. Data-at-rest protection
- Browser profile folder (`./profile/`) is compressed and encrypted into `./profile.enc` using `Fernet` (AES + HMAC).
- On lock or app exit:
  - profile data is encrypted
  - plaintext `./profile/` is removed
- On successful login:
  - `profile.enc` is decrypted back to `./profile/`
  - profile permissions are hardened (best-effort)

4. Access control
- Browser UI is unavailable until authentication succeeds.
- After 5 failed attempts, unlock is blocked for that app run.
- Single instance enforced via `QLockFile`.

5. Runtime caveat
- While unlocked, profile data is plaintext on disk so Brave can operate.
- Physical/local compromise of a running unlocked session is out of scope.

## Profile Storage

When unlocked, `./profile/` contains:

```
profile/
  cookies/
  cache/
  history/
  sessions/
  downloads/
  brave-user-data/   # Brave native profile used by --user-data-dir
```

When locked/closed, this plaintext folder is removed and stored as encrypted `profile.enc`.

## Portability (Move To Another Computer)

To keep all your data exactly as-is on another machine:

1. Close Secure Brave (and regular Brave).
2. Copy the full `dist/` folder.
3. On the new machine, keep these files together in the same folder:
   - `main.exe`
   - `app_state.json`
   - `profile.enc`
4. Run `main.exe` and unlock with your existing master password.

Notes:
- Your browsing data is inside `profile.enc` (encrypted), so copying that file preserves your full profile.
- If Brave is installed in a different path on the new machine, the launcher will ask for `brave.exe` once.

## Brave Requirement

- This launcher requires installed Brave browser (`brave.exe`).
- On first run it auto-detects common install paths; if not found, it prompts you to select the executable.

## Install

```bash
pip install -r requirements.txt
```

## Run (dev)

```bash
python main.py
```

## Package to Standalone EXE

With icon (if `icon.ico` exists):

```bash
pyinstaller --onefile --windowed --icon=icon.ico main.py
```

Without icon:

```bash
pyinstaller --onefile --windowed main.py
```

Output executable is created in `dist/main.exe` and runs without a Python installation on target machines.

## Optional Assets

- Place a custom `icon.ico` beside `main.py` for app and tray icon branding.
