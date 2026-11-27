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
import uuid
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAX_ACCOUNTS = 4
MIN_PASSWORD_LEN = 10
SCRYPT = {"n": 2**15, "r": 8, "p": 1}


class WrongPasswordError(Exception):
    pass


class WrongRecoveryKeyError(Exception):
    pass


class WeakPasswordError(ValueError):
    pass


class AccountLimitError(Exception):
    pass


class UsernameTakenError(Exception):
    pass


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text)


def _derive(secret: str, salt: bytes, params: dict) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=params["n"], r=params["r"], p=params["p"])
    return base64.urlsafe_b64encode(kdf.derive(secret.encode("utf-8")))


# The data key encrypts the entries. It is stored wrapped twice:
# once by the password, once by the recovery key.
def _wrap(data_key: bytes, secret: str, params: dict) -> dict:
    salt = secrets.token_bytes(16)
    token = Fernet(_derive(secret, salt, params)).encrypt(data_key)
    return {"salt": _b64(salt), "wrapped": token.decode("ascii")}


def _unwrap(block: dict, secret: str, params: dict) -> bytes:
    key = _derive(secret, _unb64(block["salt"]), params)
    return Fernet(key).decrypt(block["wrapped"].encode("ascii"))


def _encrypt_entries(data_key: bytes, entries: list) -> str:
    return Fernet(data_key).encrypt(json.dumps(entries).encode("utf-8")).decode("ascii")


def new_recovery_key() -> str:
    raw = base64.b32encode(secrets.token_bytes(20)).decode("ascii")  # 32 chars
    return "-".join(raw[i:i + 4] for i in range(0, 32, 4))


def _norm_recovery(key: str) -> str:
    return key.replace("-", "").replace(" ", "").upper()


def check_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LEN:
        raise WeakPasswordError(f"At least {MIN_PASSWORD_LEN} characters")


def _write_private(path: Path, content: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(content, f)
    os.replace(tmp, path)  # atomic: no half-written file


def read_backup(path, backup_password: str) -> dict:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if raw.get("kind") != "simorgh-backup":
        raise ValueError("Not a Simorgh backup file")
    kdf = raw["kdf"]
    if kdf["n"] > 2**17 or kdf["r"] > 16 or kdf["p"] > 4:
        raise ValueError("Unsupported backup parameters")
    key = _derive(backup_password, _unb64(raw["salt"]), kdf)
    try:
        plain = Fernet(key).decrypt(raw["data"].encode("ascii"))
    except InvalidToken:
        raise WrongPasswordError("Wrong backup password or corrupted file") from None
    return json.loads(plain)


class Account:
    def __init__(self, path: Path):
        self.path = Path(path)
        header = self._read()
        self.id = header["id"]
        self.username = header["username"]
        self.entries: list[dict] = []
        self._data_key: bytes | None = None

    def _read(self) -> dict:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _require_unlocked(self) -> None:
        if self._data_key is None:
            raise RuntimeError("Account is locked")

    @property
    def unlocked(self) -> bool:
        return self._data_key is not None

    def unlock(self, password: str) -> None:
        raw = self._read()
        try:
            data_key = _unwrap(raw["pw"], password, raw["kdf"])
            plain = Fernet(data_key).decrypt(raw["data"].encode("ascii"))
        except InvalidToken:
            raise WrongPasswordError("Wrong password or corrupted account") from None
        self._data_key = data_key
        self.entries = json.loads(plain)

    def lock(self) -> None:
        self.entries, self._data_key = [], None

    def verify_password(self, password: str) -> bool:
        raw = self._read()
        try:
            _unwrap(raw["pw"], password, raw["kdf"])
            return True
        except InvalidToken:
            return False

    def save(self) -> None:
        self._require_unlocked()
        raw = self._read()
        raw["data"] = _encrypt_entries(self._data_key, self.entries)
        _write_private(self.path, raw)

    def add(self, entry: dict) -> dict:
        entry = {**entry, "id": uuid.uuid4().hex}
        self.entries.append(entry)
        self.save()
        return entry

    def update(self, entry_id: str, **fields) -> None:
        for entry in self.entries:
            if entry["id"] == entry_id:
                entry.update(fields)
                self.save()
                return
        raise KeyError(entry_id)

    def remove(self, entry_id: str) -> None:
        self.entries = [e for e in self.entries if e["id"] != entry_id]
        self.save()

    def change_password(self, old: str, new: str) -> None:
        self._require_unlocked()
        check_password(new)
        if not self.verify_password(old):
            raise WrongPasswordError("Wrong password")
        raw = self._read()
        raw["pw"] = _wrap(self._data_key, new, raw["kdf"])
        _write_private(self.path, raw)

    # Returns the NEW recovery key; the old one stops working. Leaves the account unlocked.
    def reset_with_recovery(self, recovery_key: str, new_password: str) -> str:
        check_password(new_password)
        raw = self._read()
        try:
            data_key = _unwrap(raw["rec"], _norm_recovery(recovery_key), raw["kdf"])
            plain = Fernet(data_key).decrypt(raw["data"].encode("ascii"))
        except InvalidToken:
            raise WrongRecoveryKeyError("Wrong recovery key") from None
        new_key = new_recovery_key()
        raw["pw"] = _wrap(data_key, new_password, raw["kdf"])
        raw["rec"] = _wrap(data_key, _norm_recovery(new_key), raw["kdf"])
        _write_private(self.path, raw)
        self._data_key = data_key
        self.entries = json.loads(plain)
        return new_key

    # Replaces the recovery key (the old one stops working). Needs the password.
    def regenerate_recovery(self, password: str) -> str:
        self._require_unlocked()
        if not self.verify_password(password):
            raise WrongPasswordError("Wrong password")
        raw = self._read()
        new_key = new_recovery_key()
        raw["rec"] = _wrap(self._data_key, _norm_recovery(new_key), raw["kdf"])
        _write_private(self.path, raw)
        return new_key

    def export_backup(self, path, backup_password: str) -> None:
        self._require_unlocked()
        check_password(backup_password)
        params = {"name": "scrypt", **SCRYPT}
        salt = secrets.token_bytes(16)
        key = _derive(backup_password, salt, params)
        payload = json.dumps({"username": self.username, "entries": self.entries})
        _write_private(Path(path), {
            "version": 1,
            "kind": "simorgh-backup",
            "kdf": params,
            "salt": _b64(salt),
            "data": Fernet(key).encrypt(payload.encode("utf-8")).decode("ascii"),
        })

    # Adds entries not already present. Returns how many were added.
    def merge_entries(self, entries: list) -> int:
        self._require_unlocked()
        seen = {(e["issuer"], e["account"], e["secret"]) for e in self.entries}
        added = 0
        for e in entries:
            if (e["issuer"], e["account"], e["secret"]) in seen:
                continue
            self.entries.append({**e, "id": uuid.uuid4().hex})
            added += 1
        self.save()
        return added

    def delete(self, password: str) -> None:
        if not self.verify_password(password):
            raise WrongPasswordError("Wrong password")
        self.path.unlink()
        self.lock()


def default_base() -> Path:
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "simorgh"


class AccountStore:
    def __init__(self, base: Path | None = None):
        self.dir = Path(base or default_base()) / "accounts"

    def list(self) -> list[Account]:
        if not self.dir.exists():
            return []
        accounts = []
        for path in self.dir.glob("*.json"):
            try:
                accounts.append(Account(path))
            except (ValueError, KeyError, OSError):
                continue  # skip unreadable files
        return sorted(accounts, key=lambda a: a.username.lower())

    # Returns (unlocked account, recovery key). Show the key to the user once.
    def create(self, username: str, password: str, entries: list | None = None):
        username = username.strip()
        if not 1 <= len(username) <= 32:
            raise ValueError("Username must be 1-32 characters")
        check_password(password)
        existing = self.list()
        if len(existing) >= MAX_ACCOUNTS:
            raise AccountLimitError(f"Maximum {MAX_ACCOUNTS} accounts")
        if any(a.username.lower() == username.lower() for a in existing):
            raise UsernameTakenError("Username already exists")

        params = {"name": "scrypt", **SCRYPT}
        data_key = Fernet.generate_key()
        recovery = new_recovery_key()
        entries = [{**e, "id": uuid.uuid4().hex} for e in (entries or [])]
        content = {
            "version": 2,
            "id": uuid.uuid4().hex,
            "username": username,
            "kdf": params,
            "pw": _wrap(data_key, password, params),
            "rec": _wrap(data_key, _norm_recovery(recovery), params),
            "data": _encrypt_entries(data_key, entries),
        }
        path = self.dir / f"{content['id']}.json"
        _write_private(path, content)
        account = Account(path)
        account._data_key = data_key
        account.entries = entries
        return account, recovery

DEFAULT_SETTINGS = {
    "theme": "default",
    "auto_lock": 300,        # seconds, 0 = never
    "clipboard_clear": 30,   # seconds, 0 = never
    "hide_codes": False,
}


class Settings:
    def __init__(self, base: Path | None = None):
        self.path = Path(base or default_base()) / "settings.json"
        self.values = dict(DEFAULT_SETTINGS)
        try:
            saved = json.loads(self.path.read_text(encoding="utf-8"))
            for key, default in DEFAULT_SETTINGS.items():
                if isinstance(saved.get(key), type(default)):
                    self.values[key] = saved[key]
        except (OSError, ValueError, AttributeError):
            pass

    def get(self, key):
        return self.values[key]

    def set(self, key, value) -> None:
        self.values[key] = value
        _write_private(self.path, self.values)