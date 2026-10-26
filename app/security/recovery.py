"""
Recovery (backup) codes.

Codes are shown to the user exactly once, at generation. Only Argon2id hashes
are stored, so a database dump does not yield usable codes. A code is marked
used the moment it succeeds, which makes it single-use; the row is retained
rather than deleted so the audit trail stays complete.

Format: ``XXXXX-XXXXX`` using an unambiguous alphabet (no 0/O/1/I/L), which
reduces transcription errors when a user has written the codes on paper.
"""

import secrets

from flask import current_app

from ..extensions import db
from ..models import RecoveryCode, utcnow
from .passwords import hash_password, verify_password

ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # 31 symbols, no look-alikes
GROUP_LEN = 5
GROUPS = 2


def _one_code() -> str:
    parts = [
        "".join(secrets.choice(ALPHABET) for _ in range(GROUP_LEN))
        for _ in range(GROUPS)
    ]
    return "-".join(parts)


def normalise_code(raw: str) -> str:
    """Accept user input with spaces, lower case or a missing dash."""
    if not raw:
        return ""
    cleaned = "".join(ch for ch in raw.upper() if ch.isalnum())
    if len(cleaned) == GROUP_LEN * GROUPS:
        return f"{cleaned[:GROUP_LEN]}-{cleaned[GROUP_LEN:]}"
    return cleaned


def generate_recovery_codes(user, count: int | None = None) -> list[str]:
    """
    Replace any existing codes with a fresh set.

    Returns the plaintext codes for one-time display. The caller must not
    persist or log them.
    """
    count = count or current_app.config["RECOVERY_CODE_COUNT"]

    RecoveryCode.query.filter_by(user_id=user.id).delete(synchronize_session=False)

    plaintext: list[str] = []
    for _ in range(count):
        code = _one_code()
        plaintext.append(code)
        db.session.add(RecoveryCode(user_id=user.id, code_hash=hash_password(code)))

    db.session.flush()
    return plaintext


def consume_recovery_code(user, submitted: str) -> bool:
    """
    Verify and spend a recovery code.

    Every unused code is checked, so the work done does not depend on which
    code was supplied. Returns True and marks the code used on success.
    """
    candidate = normalise_code(submitted)
    if not candidate:
        return False

    matched = None
    for row in user.recovery_codes:
        if row.used_at is not None:
            continue
        if verify_password(row.code_hash, candidate) and matched is None:
            matched = row

    if matched is None:
        return False

    matched.used_at = utcnow()
    db.session.flush()
    return True
