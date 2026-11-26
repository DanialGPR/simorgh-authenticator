import pytest

import simorgh.storage as storage
from simorgh.storage import (
    AccountLimitError, AccountStore, UsernameTakenError, WeakPasswordError,
    WrongPasswordError, WrongRecoveryKeyError, read_backup,
)

PW = "correct horse battery"
ENTRY = {"issuer": "GitHub", "account": "me", "secret": "JBSWY3DPEHPK3PXP",
         "digits": 6, "period": 30, "algorithm": "SHA1"}


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setitem(storage.SCRYPT, "n", 2**10)  # keep tests quick


@pytest.fixture
def store(tmp_path):
    return AccountStore(tmp_path)


def test_create_unlock_roundtrip(store):
    acc, _ = store.create("Danial", PW)
    acc.add(ENTRY)
    again = store.list()[0]
    assert again.username == "Danial"
    again.unlock(PW)
    assert again.entries[0]["issuer"] == "GitHub"
    assert "id" in again.entries[0]
    assert oct(again.path.stat().st_mode & 0o777) == "0o600"


def test_wrong_password(store):
    store.create("a", PW)
    with pytest.raises(WrongPasswordError):
        store.list()[0].unlock("wrong password!!")


def test_weak_password(store):
    with pytest.raises(WeakPasswordError):
        store.create("a", "short")


def test_account_limit(store):
    for i in range(4):
        store.create(f"user{i}", PW)
    with pytest.raises(AccountLimitError):
        store.create("user5", PW)


def test_duplicate_username(store):
    store.create("Bob", PW)
    with pytest.raises(UsernameTakenError):
        store.create("bob", PW)


def test_change_password(store):
    acc, _ = store.create("a", PW)
    acc.add(ENTRY)
    acc.change_password(PW, "new password 123")
    fresh = store.list()[0]
    with pytest.raises(WrongPasswordError):
        fresh.unlock(PW)
    fresh.unlock("new password 123")
    assert len(fresh.entries) == 1


def test_recovery(store):
    acc, recovery = store.create("a", PW)
    acc.add(ENTRY)
    fresh = store.list()[0]
    new_recovery = fresh.reset_with_recovery(
        recovery.lower().replace("-", " "), "another password!")
    assert new_recovery != recovery
    assert len(fresh.entries) == 1
    store.list()[0].unlock("another password!")
    with pytest.raises(WrongRecoveryKeyError):  # old key is dead now
        store.list()[0].reset_with_recovery(recovery, "third password!!")


def test_backup_and_restore(store, tmp_path):
    acc, _ = store.create("a", PW)
    acc.add(ENTRY)
    backup = tmp_path / "b.simorgh-backup"
    acc.export_backup(backup, "backup password!")
    with pytest.raises(WrongPasswordError):
        read_backup(backup, "wrong")
    data = read_backup(backup, "backup password!")
    assert data["username"] == "a"
    restored, _ = AccountStore(tmp_path / "other").create(
        "a", PW, entries=data["entries"])
    assert restored.entries[0]["issuer"] == "GitHub"


def test_merge_skips_duplicates(store):
    acc, _ = store.create("a", PW)
    acc.add(ENTRY)
    assert acc.merge_entries([ENTRY, {**ENTRY, "issuer": "GitLab"}]) == 1
    assert len(acc.entries) == 2


def test_remove_entry(store):
    acc, _ = store.create("a", PW)
    entry = acc.add(ENTRY)
    acc.remove(entry["id"])
    assert acc.entries == []


def test_delete_account(store):
    acc, _ = store.create("a", PW)
    with pytest.raises(WrongPasswordError):
        acc.delete("nope nope nope")
    acc.delete(PW)
    assert store.list() == []