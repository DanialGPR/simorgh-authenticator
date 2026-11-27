# Simorgh Authenticator

An offline two-factor (TOTP) code generator for GNOME. It works with any service that supports authenticator apps, and nothing ever leaves your computer.

## Features

- Works with any service that supports TOTP 2FA (6 to 8 digits, SHA-1/256/512, custom periods through `otpauth://` links)
- Up to 4 local accounts, each protected by its own master password
- Recovery key shown at sign-up, to reset a forgotten password
- Encrypted backup and restore (`.simorgh-backup`), protected by a separate backup password
- Search, edit, delete, and import of `otpauth://` links
- Per-entry notes (for example, a service's recovery codes)
- Auto-lock, clipboard auto-clear, and "hide codes until clicked"
- Light and dark theme
- Keyboard shortcuts: `Ctrl+N` add, `Ctrl+F` search, `Ctrl+L` lock, `Ctrl+,` settings

## Install

Requires Ubuntu 24.04+ or Debian 13+ (GTK 4.10+ and libadwaita 1.5+).

Download the `.deb` from the [latest release](https://github.com/DanialGPR/simorgh-authenticator/releases/latest), then:

```
sudo apt install ./simorgh-authenticator_1.0.0_all.deb
```

`apt` installs the dependencies for you (`python3-gi`, `gir1.2-gtk-4.0`, `gir1.2-adw-1`, `python3-cryptography`). Don't use plain `dpkg -i`, because it doesn't resolve them.

To remove it: `sudo apt remove simorgh-authenticator`. Your accounts stay in `~/.config/simorgh/` until you delete them.

## Run from source

```
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1
git clone https://github.com/DanialGPR/simorgh-authenticator.git
cd simorgh-authenticator
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install -e .
python -m simorgh.gui
```

To try it without touching your real data: `XDG_CONFIG_HOME=/tmp/testcfg python -m simorgh.gui`

Run the tests with `python -m pytest -v`. Build the package with `./packaging/build-deb.sh`.

## How your data is protected

- Each account has a random data key that encrypts your entries (Fernet: AES-128-CBC with HMAC-SHA256).
- The data key is stored twice, wrapped by a key derived from your password and by one derived from your recovery key. Both derivations use scrypt (N=2^15, r=8, p=1).
- Changing your password re-wraps the data key without re-encrypting your entries.
- Files are stored in `~/.config/simorgh/` with owner-only permissions.

**Important:**

- **There is no password recovery without your recovery key.** If you lose both, your data cannot be restored. Keep a backup and store your recovery key somewhere safe.
- Unlocked secrets are held in memory while the app is open. Auto-lock helps, but a compromised computer is a compromised authenticator.
- Clipboard clearing is best-effort. Another program may copy the clipboard before it clears.
- Codes depend on your system clock. If your codes are rejected, check that your time is synchronised.
- This project has not been independently audited.

## Not supported yet (Coming Soon)

HOTP (counter-based), push approvals, SMS, hardware keys (FIDO2), Steam Guard, and scanning QR codes. Paste the secret key or `otpauth://` link instead.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
