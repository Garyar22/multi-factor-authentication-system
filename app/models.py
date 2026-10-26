"""
SQLAlchemy models — the data layer of the MFA system.

Design notes relevant to the project report:

* Passwords are stored only as Argon2id hashes (``users.password_hash``).
* TOTP secrets are stored encrypted with Fernet (``mfa_credentials.secret_encrypted``);
  the key lives in the environment, never in the database.
* Recovery codes are stored only as salted hashes (``recovery_codes.code_hash``)
  and are marked used rather than deleted, so the audit trail stays intact.
* Password reset tokens are stored as SHA-256 digests, never in plaintext.
* ``audit_events`` never receives a password, OTP value, recovery code or
  session identifier — see app/security/audit.py.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import relationship

from .extensions import db


def utcnow() -> datetime:
    """Timezone-aware UTC now. Stored naive-UTC for MySQL DATETIME columns."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Roles and users
# ---------------------------------------------------------------------------

class Role(db.Model):
    """A named role. Two are seeded: 'admin' and 'user'."""

    __tablename__ = "roles"

    id = db.Column(Integer, primary_key=True)
    name = db.Column(String(32), unique=True, nullable=False, index=True)
    description = db.Column(String(255), nullable=True)
    created_at = db.Column(DateTime, nullable=False, default=utcnow)

    users = relationship("User", back_populates="role")

    def __repr__(self) -> str:
        return f"<Role {self.name}>"


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(Integer, primary_key=True)
    username = db.Column(String(64), unique=True, nullable=False, index=True)
    email = db.Column(String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(String(255), nullable=False)
    full_name = db.Column(String(120), nullable=True)

    role_id = db.Column(Integer, ForeignKey("roles.id"), nullable=False, index=True)

    is_active = db.Column(Boolean, nullable=False, default=True)
    mfa_enabled = db.Column(Boolean, nullable=False, default=False)

    # Brute-force state. Kept on the user row so a lockout survives restarts,
    # unlike the in-memory rate limiter.
    failed_login_count = db.Column(Integer, nullable=False, default=0)
    locked_until = db.Column(DateTime, nullable=True)
    last_login_at = db.Column(DateTime, nullable=True)
    password_changed_at = db.Column(DateTime, nullable=True)

    created_at = db.Column(DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    role = relationship("Role", back_populates="users")
    mfa_credential = relationship(
        "MfaCredential",
        back_populates="user",
        uselist=False,
        cascade="all, delete-orphan",
    )
    recovery_codes = relationship(
        "RecoveryCode", back_populates="user", cascade="all, delete-orphan"
    )
    reset_tokens = relationship(
        "PasswordResetToken", back_populates="user", cascade="all, delete-orphan"
    )
    audit_events = relationship("AuditEvent", back_populates="user")

    __table_args__ = (
        Index("ix_users_role_active", "role_id", "is_active"),
    )

    # ------------------------------------------------------------- helpers ---
    @property
    def is_admin(self) -> bool:
        return bool(self.role and self.role.name == "admin")

    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > utcnow()

    def lock_for(self, minutes: int) -> None:
        self.locked_until = utcnow() + timedelta(minutes=minutes)

    def unlock(self) -> None:
        self.locked_until = None
        self.failed_login_count = 0

    def unused_recovery_code_count(self) -> int:
        return sum(1 for c in self.recovery_codes if not c.used_at)

    def __repr__(self) -> str:
        return f"<User {self.username}>"


# ---------------------------------------------------------------------------
# MFA credential
# ---------------------------------------------------------------------------

class MfaCredential(db.Model):
    """One TOTP credential per user. The secret is encrypted at rest."""

    __tablename__ = "mfa_credentials"

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(
        Integer, ForeignKey("users.id"), unique=True, nullable=False, index=True
    )

    secret_encrypted = db.Column(Text, nullable=False)
    method = db.Column(String(16), nullable=False, default="totp")
    confirmed_at = db.Column(DateTime, nullable=True)

    # Replay protection: the last TOTP counter (time step) that was accepted.
    # A code from the same or an earlier step is refused even if still inside
    # the clock-skew window.
    last_used_counter = db.Column(Integer, nullable=True)

    created_at = db.Column(DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(DateTime, nullable=False, default=utcnow, onupdate=utcnow)

    user = relationship("User", back_populates="mfa_credential")

    @property
    def is_confirmed(self) -> bool:
        return self.confirmed_at is not None

    def __repr__(self) -> str:
        return f"<MfaCredential user_id={self.user_id} confirmed={self.is_confirmed}>"


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------

class RecoveryCode(db.Model):
    """Single-use backup code. Only a hash of the code is stored."""

    __tablename__ = "recovery_codes"

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    code_hash = db.Column(String(255), nullable=False)
    used_at = db.Column(DateTime, nullable=True)
    created_at = db.Column(DateTime, nullable=False, default=utcnow)

    user = relationship("User", back_populates="recovery_codes")

    __table_args__ = (
        Index("ix_recovery_user_used", "user_id", "used_at"),
    )

    @property
    def is_used(self) -> bool:
        return self.used_at is not None


# ---------------------------------------------------------------------------
# Password reset tokens
# ---------------------------------------------------------------------------

class PasswordResetToken(db.Model):
    """Expiring, single-use reset token. Stored as a SHA-256 digest."""

    __tablename__ = "password_reset_tokens"

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    token_hash = db.Column(String(64), unique=True, nullable=False, index=True)
    expires_at = db.Column(DateTime, nullable=False)
    used_at = db.Column(DateTime, nullable=True)
    created_at = db.Column(DateTime, nullable=False, default=utcnow)

    user = relationship("User", back_populates="reset_tokens")

    def is_valid(self) -> bool:
        return self.used_at is None and self.expires_at > utcnow()


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class AuditEvent(db.Model):
    """
    Append-only security event record.

    The application never issues UPDATE or DELETE against this table; only
    INSERT and SELECT are used, and the documented MySQL grant for the
    application account reflects that (see docs/DEPLOYMENT.md).
    """

    __tablename__ = "audit_events"

    id = db.Column(Integer, primary_key=True)
    event_type = db.Column(String(64), nullable=False, index=True)
    category = db.Column(String(32), nullable=False, default="auth", index=True)
    outcome = db.Column(String(16), nullable=False, default="success", index=True)

    user_id = db.Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    # Kept separately so an event survives the user row being removed, and so
    # failed logins for a non-existent username are still recorded.
    username_attempted = db.Column(String(64), nullable=True)

    ip_address = db.Column(String(45), nullable=True)   # fits IPv6
    user_agent = db.Column(String(255), nullable=True)
    detail = db.Column(String(255), nullable=True)

    created_at = db.Column(
        DateTime, nullable=False, default=utcnow, server_default=func.now(), index=True
    )

    user = relationship("User", back_populates="audit_events")

    __table_args__ = (
        Index("ix_audit_type_created", "event_type", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<AuditEvent {self.event_type} {self.outcome} {self.created_at}>"


class PendingAuthentication(db.Model):
    """
    Server-side record of the half-authenticated state between a correct
    password and a verified second factor.

    Holding this server-side (rather than in a client cookie alone) means a
    user who tampers with their cookie cannot promote themselves to a fully
    authenticated session: the session cookie carries only an opaque id, and
    every check is made against this row.
    """

    __tablename__ = "pending_authentications"

    id = db.Column(Integer, primary_key=True)
    token = db.Column(String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    expires_at = db.Column(DateTime, nullable=False)
    attempts = db.Column(Integer, nullable=False, default=0)
    consumed_at = db.Column(DateTime, nullable=True)
    ip_address = db.Column(String(45), nullable=True)
    created_at = db.Column(DateTime, nullable=False, default=utcnow)

    user = relationship("User")

    def is_valid(self) -> bool:
        return self.consumed_at is None and self.expires_at > utcnow()

    __table_args__ = (
        UniqueConstraint("token", name="uq_pending_token"),
    )
