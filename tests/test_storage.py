import pytest
from simorgh.storage import Vault, WrongPasswordError


def test_roundtrip(tmp_path):
    path = tmp_path / "vault.json"
    v = Vault(path)
    v.create("pw123")
    v.add({"issuer": "GitHub", "account": "me", "secret": "JBSWY3DPEHPK3PXP",
           "digits": 6, "period": 30, "algorithm": "SHA1"})

    v2 = Vault(path)
    v2.unlock("pw123")
    assert v2.entries[0]["issuer"] == "GitHub"
    assert oct(path.stat().st_mode & 0o777) == "0o600"


def test_wrong_password(tmp_path):
    path = tmp_path / "vault.json"
    Vault(path).create("right")
    with pytest.raises(WrongPasswordError):
        Vault(path).unlock("wrong")