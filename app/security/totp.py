"""
TOTP generation, verification and replay prevention (RFC 6238).

Verification policy implemented here, and the reasoning behind it:

1. **Clock-skew window.** A device whose clock is slightly off would otherwise
   be unable to log in, so codes from one step either side of the current step
   are accepted (``TOTP_VALID_WINDOW = 1``, i.e. about 90 seconds in total with
   a 30-second step). Widening the window improves usability but lengthens the
   period in which a code intercepted by an attacker remains usable, so it is
   kept at the smallest value that tolerates ordinary clock drift.

2. **Replay prevention.** Within that window the same code would normally work
   more than once. Each credential therefore records the counter (time step)
   of the last accepted code, and a code whose counter is less than or equal to
   that value is refused. An attacker who shoulder-surfs or phishes a code and
   replays it after the legitimate user has used it gets nothing.

   The trade-off is that the user cannot log in twice inside the same 30-second
   step; they must wait for the next code. That is a deliberate choice in favour
   of security, and it is documented in the user manual.

3. **Scope.** TOTP defends against a compromised password (credential stuffing,
   database leaks, weak passwords). It is *not* phishing-resistant: a real-time
   phishing proxy can relay a code within its validity window. Phishing
   resistance needs origin-bound credentials such as WebAuthn/passkeys, which
   are discussed as future work in docs/LIMITATIONS.md.
"""

import time

import pyotp
from flask import current_app


def generate_secret() -> str:
    """Return a fresh base32 TOTP secret (160 bits, per RFC 4226 guidance)."""
    return pyotp.random_base32()


def _totp(secret: str) -> pyotp.TOTP:
    cfg = current_app.config
    return pyotp.TOTP(
        secret,
        interval=cfg["TOTP_INTERVAL"],
        digits=cfg["TOTP_DIGITS"],
    )


def current_counter(at: float | None = None) -> int:
    """The current RFC 6238 time step, used for replay bookkeeping."""
    interval = current_app.config["TOTP_INTERVAL"]
    return int((at if at is not None else time.time()) // interval)


def provisioning_uri(secret: str, account_name: str) -> str:
    """
    Build the otpauth:// URI that authenticator apps consume.

    Format: otpauth://totp/Issuer:account?secret=...&issuer=...
    """
    return _totp(secret).provisioning_uri(
        name=account_name,
        issuer_name=current_app.config["MFA_ISSUER_NAME"],
    )


def generate_code(secret: str, at: float | None = None) -> str:
    """
    Generate the code for a given moment.

    ``time.time()`` is used as the single clock source for both generation and
    verification. pyotp's own ``now()`` reads the clock through a different
    call, and mixing the two would mean generation and verification could
    disagree about which time step they are in.
    """
    return _totp(secret).at(at if at is not None else time.time())


def find_matching_counter(secret: str, code: str, at: float | None = None) -> int | None:
    """
    Verify ``code`` and return the counter that matched, or None.

    Returning the counter (rather than just True/False) is what makes replay
    prevention possible: the caller stores it and refuses anything not strictly
    greater next time.
    """
    if not code:
        return None
    code = code.strip().replace(" ", "")
    digits = current_app.config["TOTP_DIGITS"]
    if not code.isdigit() or len(code) != digits:
        return None

    window = current_app.config["TOTP_VALID_WINDOW"]
    interval = current_app.config["TOTP_INTERVAL"]
    now = at if at is not None else time.time()
    totp = _totp(secret)
    base = int(now // interval)

    for offset in range(-window, window + 1):
        counter = base + offset
        # pyotp compares in constant time internally (hmac.compare_digest).
        if totp.verify(code, for_time=counter * interval, valid_window=0):
            return counter
    return None


def verify_code(
    secret: str,
    code: str,
    last_used_counter: int | None = None,
    at: float | None = None,
) -> tuple[bool, int | None, str]:
    """
    Full verification including replay check.

    Returns ``(accepted, counter, reason)``. ``reason`` is one of
    ``"ok"``, ``"invalid"`` or ``"replay"`` and is used for audit detail —
    never shown verbatim to the user, so an attacker cannot learn whether a
    code was wrong or merely already spent.
    """
    counter = find_matching_counter(secret, code, at=at)
    if counter is None:
        return False, None, "invalid"
    if last_used_counter is not None and counter <= last_used_counter:
        return False, counter, "replay"
    return True, counter, "ok"
