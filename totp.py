"""
NetSecureX - Time-based one-time passwords (RFC 6238), standard library only.

Used for optional two-factor sign-in. Each user who enables it gets a random
base32 secret, which they add to an authenticator app (Google Authenticator,
Microsoft Authenticator, and similar). Codes are 6 digits, change every 30
seconds, and are accepted within one step either side to allow for clock drift.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP_SECONDS = 30
DIGITS = 6


def generate_secret(num_bytes=20):
    """Random secret, base32-encoded without padding (the form apps expect)."""
    return base64.b32encode(secrets.token_bytes(num_bytes)).decode("ascii").rstrip("=")


def _key(secret_b32):
    padded = secret_b32.upper() + "=" * (-len(secret_b32) % 8)
    return base64.b32decode(padded)


def totp_at(secret_b32, unix_time, digits=DIGITS, step=STEP_SECONDS):
    counter = int(unix_time // step)
    digest = hmac.new(_key(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify(secret_b32, code, now=None, window=1):
    """True if `code` matches the current step or `window` steps either side."""
    if not secret_b32 or not code or not code.isdigit() or len(code) != DIGITS:
        return False
    now = time.time() if now is None else now
    for offset in range(-window, window + 1):
        if hmac.compare_digest(totp_at(secret_b32, now + offset * STEP_SECONDS), code):
            return True
    return False


def provisioning_uri(secret_b32, username, issuer="NetSecureX"):
    label = quote(f"{issuer}:{username}")
    return (f"otpauth://totp/{label}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&digits={DIGITS}&period={STEP_SECONDS}")
