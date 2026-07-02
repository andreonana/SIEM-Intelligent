# backend/tests/unit/s3/test_mfa.py
#
# Tests unitaires du module MFA TOTP (RFC 6238).
# Lance avec : python3 -m pytest tests/unit/s3/test_mfa.py -v

import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pyotp
import pytest

from app.modules.rbac.mfa import (
    generate_totp_secret,
    get_provisioning_uri,
    verify_totp_code,
    create_mfa_pending_token,
    decode_mfa_pending_token,
)


# ---------------------------------------------------------------------------
# generate_totp_secret
# ---------------------------------------------------------------------------

class TestGenerateTotpSecret:
    def test_returns_base32_string(self):
        secret = generate_totp_secret()
        assert isinstance(secret, str)
        # Base32 = uppercase A-Z + 2-7, multiple de 8 après décodage
        import base64
        base64.b32decode(secret)  # lève ValueError si invalide

    def test_unique_per_call(self):
        secrets = {generate_totp_secret() for _ in range(10)}
        assert len(secrets) == 10

    def test_minimum_length(self):
        # Un secret pyotp.random_base32() est de 32 caractères (160 bits)
        secret = generate_totp_secret()
        assert len(secret) >= 16


# ---------------------------------------------------------------------------
# get_provisioning_uri
# ---------------------------------------------------------------------------

class TestGetProvisioningUri:
    def test_scheme(self):
        secret = generate_totp_secret()
        uri = get_provisioning_uri(secret, "alice")
        assert uri.startswith("otpauth://totp/")

    def test_contains_username(self):
        secret = generate_totp_secret()
        uri = get_provisioning_uri(secret, "testuser")
        assert "testuser" in uri

    def test_contains_secret(self):
        secret = generate_totp_secret()
        uri = get_provisioning_uri(secret, "bob")
        assert f"secret={secret}" in uri

    def test_contains_issuer(self):
        secret = generate_totp_secret()
        uri = get_provisioning_uri(secret, "carol")
        assert "Smart%20SIEM" in uri or "Smart+SIEM" in uri or "Smart SIEM" in uri


# ---------------------------------------------------------------------------
# verify_totp_code
# ---------------------------------------------------------------------------

class TestVerifyTotpCode:
    def _valid_code(self, secret: str) -> str:
        return pyotp.TOTP(secret).now()

    def test_valid_current_code(self):
        secret = generate_totp_secret()
        code = self._valid_code(secret)
        assert verify_totp_code(secret, code) is True

    def test_invalid_code(self):
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "000000") is False

    def test_wrong_format_alpha(self):
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "abcdef") is False

    def test_wrong_length(self):
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "12345") is False

    def test_empty_code(self):
        secret = generate_totp_secret()
        assert verify_totp_code(secret, "") is False

    def test_empty_secret(self):
        assert verify_totp_code("", "123456") is False

    def test_none_secret(self):
        assert verify_totp_code(None, "123456") is False  # type: ignore

    def test_spaces_stripped(self):
        secret = generate_totp_secret()
        code = self._valid_code(secret)
        assert verify_totp_code(secret, f" {code} ") is True

    def test_wrong_secret(self):
        secret1 = generate_totp_secret()
        secret2 = generate_totp_secret()
        code = self._valid_code(secret1)
        assert verify_totp_code(secret2, code) is False


# ---------------------------------------------------------------------------
# create_mfa_pending_token / decode_mfa_pending_token
# ---------------------------------------------------------------------------

class TestMfaPendingToken:
    def test_roundtrip(self):
        token = create_mfa_pending_token("42", "alice")
        payload = decode_mfa_pending_token(token)
        assert payload["sub"] == "42"
        assert payload["username"] == "alice"
        assert payload["mfa_pending"] is True

    def test_expired_token_raises(self):
        from jose import jwt as jose_jwt
        import os
        secret = os.getenv("JWT_SECRET", "dev-jwt-secret-must-be-min-32-chars-long")
        expired_payload = {
            "sub": "1",
            "username": "bob",
            "mfa_pending": True,
            "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
        }
        token = jose_jwt.encode(expired_payload, secret, algorithm="HS256")
        with pytest.raises(ValueError, match="expiré"):
            decode_mfa_pending_token(token)

    def test_non_mfa_token_raises(self):
        from jose import jwt as jose_jwt
        import os
        secret = os.getenv("JWT_SECRET", "dev-jwt-secret-must-be-min-32-chars-long")
        payload = {
            "sub": "1",
            "username": "carol",
            "mfa_pending": False,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }
        token = jose_jwt.encode(payload, secret, algorithm="HS256")
        with pytest.raises(ValueError, match="intermédiaire"):
            decode_mfa_pending_token(token)

    def test_garbage_token_raises(self):
        with pytest.raises(ValueError):
            decode_mfa_pending_token("not-a-jwt-at-all")

    def test_tampered_token_raises(self):
        token = create_mfa_pending_token("1", "dave")
        tampered = token[:-4] + "xxxx"
        with pytest.raises(ValueError):
            decode_mfa_pending_token(tampered)
