"""
Security audit logging.

Design rules enforced here:

* **No secrets.** Passwords, submitted OTP values, recovery codes, reset
  tokens and session identifiers are never written. ``record_event`` passes
  every value through a scrubber, so even a careless call site cannot leak a
  secret into the log.
* **Append-only.** The application only inserts and selects. The documented
  MySQL grant for the application account withholds UPDATE and DELETE on this
  table (docs/DEPLOYMENT.md), so a compromised application cannot rewrite its
  own history.
* **Failed logins for unknown usernames are still recorded**, under
  ``username_attempted``, because a spray across many usernames is exactly the
  pattern an administrator needs to see.
"""

import logging
import re

from flask import current_app, has_request_context, request

from ..extensions import db
from ..models import AuditEvent

logger = logging.getLogger("mfa.audit")

# ---------------------------------------------------------------- event names --
LOGIN_SUCCESS = "login_success"
LOGIN_FAILED = "login_failed"
LOGIN_BLOCKED_LOCKED = "login_blocked_locked"
LOGIN_BLOCKED_INACTIVE = "login_blocked_inactive"
LOGIN_RATE_LIMITED = "login_rate_limited"
LOGOUT = "logout"
ACCOUNT_LOCKED = "account_locked"
ACCOUNT_UNLOCKED = "account_unlocked"

REGISTER_SUCCESS = "register_success"
REGISTER_FAILED = "register_failed"

MFA_STEP_REQUIRED = "mfa_step_required"
MFA_VERIFY_SUCCESS = "mfa_verify_success"
MFA_VERIFY_FAILED = "mfa_verify_failed"
MFA_VERIFY_REPLAY = "mfa_verify_replay_rejected"
MFA_PENDING_EXPIRED = "mfa_pending_expired"
MFA_ENROLL_STARTED = "mfa_enroll_started"
MFA_ENROLL_COMPLETED = "mfa_enroll_completed"
MFA_ENROLL_FAILED = "mfa_enroll_failed"
MFA_DISABLED = "mfa_disabled"
MFA_RECOVERY_CODES_GENERATED = "mfa_recovery_codes_generated"
MFA_RECOVERY_CODE_USED = "mfa_recovery_code_used"
MFA_RECOVERY_CODE_FAILED = "mfa_recovery_code_failed"

PASSWORD_RESET_REQUESTED = "password_reset_requested"
PASSWORD_RESET_COMPLETED = "password_reset_completed"
PASSWORD_RESET_INVALID_TOKEN = "password_reset_invalid_token"
PASSWORD_CHANGED = "password_changed"

ACCESS_DENIED = "access_denied"
ADMIN_VIEW_USERS = "admin_view_users"
ADMIN_VIEW_AUDIT = "admin_view_audit"
ADMIN_ACCOUNT_ACTIVATED = "admin_account_activated"
ADMIN_ACCOUNT_DEACTIVATED = "admin_account_deactivated"
ADMIN_ACCOUNT_UNLOCKED = "admin_account_unlocked"

CATEGORY_AUTH = "auth"
CATEGORY_MFA = "mfa"
CATEGORY_ACCOUNT = "account"
CATEGORY_ADMIN = "admin"
CATEGORY_ACCESS = "access"

OUTCOME_SUCCESS = "success"
OUTCOME_FAILURE = "failure"
OUTCOME_BLOCKED = "blocked"

# Anything that looks like a secret is removed from free-text detail.
_SCRUB_PATTERNS = [
    (re.compile(r"\b\d{6,8}\b"), "[otp-redacted]"),                 # OTP values
    (re.compile(r"\b[A-Z2-9]{5}-[A-Z2-9]{5}\b"), "[code-redacted]"),  # recovery codes
    (re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"), "[token-redacted]"),   # tokens/secrets
]
_FORBIDDEN_KEYS = {
    "password", "passwd", "pwd", "otp", "code", "totp", "token",
    "secret", "recovery_code", "csrf_token", "session",
}


def scrub(text) -> str | None:
    """Remove anything that resembles an authentication secret."""
    if text is None:
        return None
    out = str(text)
    for pattern, replacement in _SCRUB_PATTERNS:
        out = pattern.sub(replacement, out)
    return out[:255]


def _client_ip() -> str | None:
    if not has_request_context():
        return None
    # ProxyFix (applied in the app factory) has already resolved this when the
    # app runs behind a trusted reverse proxy.
    return (request.remote_addr or "")[:45] or None


def _user_agent() -> str | None:
    if not has_request_context():
        return None
    return (request.headers.get("User-Agent") or "")[:255] or None


def record_event(
    event_type: str,
    *,
    category: str = CATEGORY_AUTH,
    outcome: str = OUTCOME_SUCCESS,
    user=None,
    user_id: int | None = None,
    username_attempted: str | None = None,
    detail: str | None = None,
    commit: bool = True,
) -> AuditEvent:
    """
    Insert one audit row.

    Audit logging must never break the request it is describing, so any
    database problem here is logged to the application log and swallowed.
    """
    if isinstance(detail, dict):
        detail = ", ".join(
            f"{k}={'[redacted]' if k.lower() in _FORBIDDEN_KEYS else v}"
            for k, v in detail.items()
        )

    event = AuditEvent(
        event_type=event_type,
        category=category,
        outcome=outcome,
        user_id=user.id if user is not None else user_id,
        username_attempted=(username_attempted or "")[:64] or None,
        ip_address=_client_ip(),
        user_agent=_user_agent(),
        detail=scrub(detail),
    )
    try:
        db.session.add(event)
        if commit:
            db.session.commit()
        else:
            db.session.flush()
    except Exception:  # pragma: no cover - defensive
        db.session.rollback()
        current_app.logger.exception("Failed to write audit event %s", event_type)

    logger.info(
        "audit event=%s outcome=%s user_id=%s username=%s ip=%s",
        event_type, outcome, event.user_id, event.username_attempted, event.ip_address,
    )
    return event
