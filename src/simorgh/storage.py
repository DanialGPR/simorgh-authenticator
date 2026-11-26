# Cyber Security Project 01 - 2FA Code Generator
# Encryptes vault for TOTP entries
# Date of Development: November 2026
# Developrt: Danial Gholipour
# BSc. Computer Engineering - Software
# Islamic Azad University - Karaj Branch
# ORCID: 0009-0004-1372-5307



#---------------------------------------------------------------

import base64
import json
import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1


class WrongPasswordError(Exception):
    pass

def default_vault_path() -> Path:
    base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "simorgh" / "vault.json"


def _derive_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


class Vault:
    def __init__(self, path: Path | None = None):
        self.path = path or default_vault_path()
        self.entries: list[dict] = []
        self._key: bytes | None = None
        self._salt: bytes | None = None

    def exists(self) -> bool:
        return self.path.exists()

    def create(self, password: str) -> None:
        if self.exists():
            raise FileExistsError(f"Vault already exists: {self.path}")
        self._salt = secrets.token_bytes(16)
        self._key = _derive_key(password, self._salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
        self.entries = []
        self.save()

    def unlock(self, password: str) -> None:
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        kdf = raw["kdf"]
        salt = base64.b64decode(kdf["salt"])
        key = _derive_key(password, salt, kdf["n"], kdf["r"], kdf["p"])
        try:
            plain = Fernet(key).decrypt(raw["data"].encode("ascii"))
        except InvalidToken:
            raise WrongPasswordError("Wrong password or corrupted vault!") from None
        self._salt, self._key = salt, key
        self.entries = json.loads(plain)

    def lock(self) -> None:
        self.entries, self._key, self._salt = [], None, None

    def save(self) -> None:
        if self._key is None or self._salt is None:
            raise RuntimeError("Vault is locked")
        token = Fernet(self._key).encrypt(json.dumps(self.entries).encode("utf-8"))
        content = {
            "version": 1,
            "kdf": {
                "name": "scrypt",
                "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
                "salt": base64.b64encode(self._salt).decode("ascii"),
            },
            "data": token.decode("ascii"),
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(content, f)
        os.replace(tmp, self.path)  # atomic: no half-written vault

    def add(self, entry: dict) -> None:
        self.entries.append(entry)
        self.save()

    def remove(self, index: int) -> None:
        del self.entries[index]
        self.save()