# ============================================================
# mfa.py — Multi-Factor Authentication (TOTP)
# Handles: generating and verifying 6-digit MFA codes
# ============================================================

import pyotp
import qrcode
import io
import base64

def generate_mfa_secret() -> str:
    """
    Generates a unique secret key for a user's MFA setup.
    Store this in the database when the user enables MFA.
    """
    return pyotp.random_base32()


def generate_qr_code(username: str, secret: str) -> str:
    """
    Generates a QR code the user scans with Google Authenticator.
    Returns a base64 string to display as an image in the frontend.

    Frontend usage:
        <img src="data:image/png;base64,{qr_base64}">
    """
    totp = pyotp.TOTP(secret)
    otp_uri = totp.provisioning_uri(
        name=username,
        issuer_name="SMART SIEM CTU"
    )
    qr = qrcode.make(otp_uri)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    buffer.seek(0)
    return base64.b64encode(buffer.getvalue()).decode("utf-8")


def verify_mfa_code(secret: str, code: str) -> bool:
    """
    Verifies the 6-digit code the user types from their phone.
    Returns True if correct, False if wrong or expired.

    Usage:
        is_valid = verify_mfa_code(user_secret, "482910")
        if not is_valid:
            raise HTTPException(401, "Invalid MFA code")
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)
