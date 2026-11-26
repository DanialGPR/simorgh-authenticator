# Cyber Security Project 01 - 2FA Code Generator
# Core app code
# Date of Development: November 2026
# Developrt: Danial Gholipour
# BSc. Computer Engineering - Software
# Islamic Azad University - Karaj Branch
# ORCID: 0009-0004-1372-5307



#---------------------------------------------------------------

import base64
import hashlib
import hmac
import struct
import time
from urllib.parse import urlparse, parse_qs, unquote

_ALGORITHMS = {
        "SHA1": hashlib.sha1,
        "SHA256": hashlib.sha256,
        "SHA512": hashlib.sha512,
}


def decode_secret(secret_b32: str) -> bytes:
    cleaned = secret_b32.replace(" ", "").replace("-", "").upper()
    cleaned += "=" * (-len(cleaned) % 8)
    return base64.b32decode(cleaned)

def hotp(key: bytes, counter: int, digits: int = 6, algorithm: str = "SHA1") -> str:
    digest_fn = _ALGORITHMS[algorithm.upper()]
    msg = struct.pack(">Q", counter)
    mac = hmac.new(key, msg, digest_fn).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10 ** digits)).zfill(digits)

def generate_totp(
        secret_b32: str,
        digits: int = 6,
        period: int = 30,
        algorithm: str = "SHA1",
        at_time: float | None = None,
) -> str:
    if at_time is None:
        at_time = time.time()
    counter = int(at_time // period)
    return hotp(decode_secret(secret_b32), counter, digits, algorithm)


def seconds_remaining(period: int = 30, at_time: float | None = None) -> int:
    if at_time is None:
        at_time = time.time()
    return period - int(at_time % period)

def parse_otpauth_uri(uri: str) -> dict:
    parsed = urlparse(uri)
    if parsed.scheme != "otpauth" or parsed.netloc != "totp":
        raise ValueError("Only otpauth://totp/ URIs are supported!")
    label = unquote(parsed.path.lstrip("/"))
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    if "secret" not in params:
        raise ValueError("URI has no secret!")
    issuer, _, account = label.partition(":")
    if not account:
        issuer, account = params.get("issuer", ""), label
    return {
        "issuer": params.get("issuer", issuer),
        "account": account.strip(),
        "secret": params["secret"],
        "digits": int(params.get("digits", 6)),
        "period": int(params.get("period"), 30),
        "algorithm": params.get("algorithm", "SHA1").upper(),
    }

