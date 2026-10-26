"""
QR code rendering for authenticator enrollment.

The QR image is generated in-process and returned as a base64 ``data:`` URI
embedded in the page. Nothing is written to disk and no third-party service
sees the secret — a QR code produced by an external API would hand the TOTP
seed to that API.
"""

import base64
import io

import qrcode
from qrcode.image.pil import PilImage


def qr_data_uri(payload: str, box_size: int = 6, border: int = 2) -> str:
    """Return a PNG data URI for the given otpauth:// payload."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(payload)
    qr.make(fit=True)

    image = qr.make_image(image_factory=PilImage, fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"
