"""
Authentication state and session management.

Three distinct states exist, and keeping them apart is what prevents an
MFA bypass:

1. **Anonymous** — no session keys set.
2. **Pending (half-authenticated)** — the password was correct but the second
   factor has not been verified. The cookie holds only an opaque token; the
   authoritative record is a ``pending_authentications`` row with an expiry and
   an attempt counter. A user in this state must not reach any protected page.
3. **Fully authenticated** — set only by :func:`complete_login`, which is
   called from exactly two places: a password-only login for an account with
   MFA disabled, and successful second-factor verification.

Session fixation is handled by clearing the session and issuing a fresh
identifier at each privilege change (login, MFA completion, password change),
so a session id an attacker planted before authentication is never promoted.
"""

from datetime import timedelta

from flask import current_app, session

from ..extensions import db
from ..models import PendingAuthentication, User, utcnow
from .crypto import generate_opaque_id

AUTH_USER_ID = "auth_user_id"
AUTH_AT = "auth_at"
AUTH_LAST_SEEN = "auth_last_seen"
AUTH_SID = "auth_sid"
PENDING_TOKEN = "pending_token"


# ---------------------------------------------------------------------------
# Pending (half-authenticated) state
# ---------------------------------------------------------------------------

def start_pending_authentication(user) -> PendingAuthentication:
    """Create the server-side pending record after a correct password."""
    from flask import request

    # Any earlier pending record for this user is invalidated, so a stale
    # half-authenticated state cannot be resumed later.
    PendingAuthentication.query.filter_by(
        user_id=user.id, consumed_at=None
    ).update({"consumed_at": utcnow()}, synchronize_session=False)

    ttl = current_app.config["MFA_PENDING_TTL_SECONDS"]
    token = generate_opaque_id(32)
    record = PendingAuthentication(
        token=token,
        user_id=user.id,
        expires_at=utcnow() + timedelta(seconds=ttl),
        ip_address=(getattr(request, "remote_addr", None) or "")[:45] or None,
    )
    db.session.add(record)
    db.session.commit()

    # Start from a clean session, with a brand-new session id, so nothing from
    # an earlier state survives and a pre-planted id cannot be reused.
    session.clear()
    _rotate(session)
    session[PENDING_TOKEN] = token
    session.permanent = True
    return record


def _rotate(sess) -> None:
    """Ask the server-side session store for a fresh session id, if supported."""
    rotate = getattr(sess, "rotate", None)
    if callable(rotate):
        rotate()


def get_pending_authentication() -> PendingAuthentication | None:
    """Return the live pending record, or None. Expired records are consumed."""
    token = session.get(PENDING_TOKEN)
    if not token:
        return None
    record = PendingAuthentication.query.filter_by(token=token).first()
    if record is None:
        session.pop(PENDING_TOKEN, None)
        return None
    if not record.is_valid():
        record.consumed_at = record.consumed_at or utcnow()
        db.session.commit()
        session.pop(PENDING_TOKEN, None)
        return None
    return record


def register_pending_attempt(record) -> bool:
    """
    Count a failed second-factor attempt.

    Returns True if further attempts are still allowed. When the cap is
    reached the pending state is destroyed, so the attacker must start again
    from the password step instead of grinding codes against one state.
    """
    record.attempts += 1
    exhausted = record.attempts >= current_app.config["MFA_PENDING_MAX_ATTEMPTS"]
    if exhausted:
        record.consumed_at = utcnow()
        session.pop(PENDING_TOKEN, None)
    db.session.commit()
    return not exhausted


def consume_pending_authentication(record) -> None:
    record.consumed_at = utcnow()
    db.session.commit()
    session.pop(PENDING_TOKEN, None)


# ---------------------------------------------------------------------------
# Full authentication
# ---------------------------------------------------------------------------

def complete_login(user) -> None:
    """
    Promote to a fully authenticated session.

    ``session.clear()`` plus a rotated session id discards the identifier the
    client arrived with, which is the standard defence against session
    fixation: an id an attacker planted before authentication is never
    promoted to an authenticated one.
    """
    session.clear()
    _rotate(session)
    session[AUTH_USER_ID] = user.id
    session[AUTH_SID] = generate_opaque_id(24)
    now = utcnow().isoformat()
    session[AUTH_AT] = now
    session[AUTH_LAST_SEEN] = now
    session.permanent = True

    user.last_login_at = utcnow()
    user.failed_login_count = 0
    user.locked_until = None
    db.session.commit()


def logout() -> None:
    """
    Sign out and genuinely revoke the session.

    Clearing the keys is not enough on its own: the stored record is deleted
    too, so a copy of the cookie captured earlier stops working immediately
    rather than remaining valid until it expires.
    """
    session.clear()
    destroy = getattr(session, "destroy", None)
    if callable(destroy):
        destroy()


def current_user() -> User | None:
    """The fully authenticated user, or None. Never returns a pending user."""
    user_id = session.get(AUTH_USER_ID)
    if not user_id:
        return None
    user = db.session.get(User, user_id)
    if user is None or not user.is_active:
        # The account was deleted or deactivated while this session was live.
        # The session is revoked at once rather than left usable.
        logout()
        return None
    return user


def is_authenticated() -> bool:
    return current_user() is not None


def touch_session() -> bool:
    """
    Enforce the idle timeout. Returns False when the session has expired and
    was cleared, which the request hook turns into a redirect to the login page.
    """
    if AUTH_USER_ID not in session:
        return True

    limit = current_app.config["SESSION_IDLE_TIMEOUT_MINUTES"]
    last_seen_raw = session.get(AUTH_LAST_SEEN)
    if last_seen_raw:
        try:
            from datetime import datetime

            last_seen = datetime.fromisoformat(last_seen_raw)
            if utcnow() - last_seen > timedelta(minutes=limit):
                logout()
                return False
        except ValueError:
            # Unparseable timestamp: treat as hostile and revoke.
            logout()
            return False

    session[AUTH_LAST_SEEN] = utcnow().isoformat()
    return True
