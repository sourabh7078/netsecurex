"""TOTP: RFC 6238 test vectors, drift window, and malformed input."""
import base64
import totp

# RFC 6238 Appendix B: SHA-1 secret "12345678901234567890".
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode("ascii").rstrip("=")


def test_rfc6238_vectors_six_digits():
    # The RFC lists 8-digit codes; the 6-digit codes are their last six digits.
    assert totp.totp_at(RFC_SECRET, 59) == "287082"
    assert totp.totp_at(RFC_SECRET, 1111111109) == "081804"
    assert totp.totp_at(RFC_SECRET, 1234567890) == "005924"


def test_verify_accepts_current_code():
    code = totp.totp_at(RFC_SECRET, 1000)
    assert totp.verify(RFC_SECRET, code, now=1000)


def test_verify_allows_one_step_of_drift():
    code = totp.totp_at(RFC_SECRET, 1000 - 30)
    assert totp.verify(RFC_SECRET, code, now=1000, window=1)


def test_verify_rejects_code_outside_window():
    code = totp.totp_at(RFC_SECRET, 1000 - 90)
    assert not totp.verify(RFC_SECRET, code, now=1000, window=1)


def test_verify_rejects_malformed_input():
    for bad in ["", "12345", "1234567", "abcdef", None]:
        assert not totp.verify(RFC_SECRET, bad, now=1000)


def test_generated_secret_is_base32_and_unique():
    a, b = totp.generate_secret(), totp.generate_secret()
    assert a != b and len(a) >= 32
    base64.b32decode(a + "=" * (-len(a) % 8))  # must decode


def test_provisioning_uri_has_expected_parts():
    uri = totp.provisioning_uri("ABCDEF", "analyst1")
    assert uri.startswith("otpauth://totp/NetSecureX%3Aanalyst1?secret=ABCDEF")
    assert "digits=6" in uri and "period=30" in uri
