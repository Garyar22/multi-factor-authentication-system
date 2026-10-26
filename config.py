"""
Application configuration.

Project : Multi-Factor Authentication (MFA) System for Securing Web Applications
Owner   : Yahye Ahmed Adan
Course  : Bachelor of Networks and Cyber Security, ISBAT University

All secrets are read from environment variables. No secret is hard-coded here.
See .env.example for the full list of variables and how to generate values.
"""

import os
from datetime import timedelta


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


class Config:
    """Settings shared by every environment."""

    # ---------------------------------------------------------------- core ---
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # Fernet key used to encrypt TOTP secrets at rest. Stored OUTSIDE the
    # database (environment variable / secret manager), so a database dump
    # alone does not reveal usable TOTP seeds.
    MFA_ENCRYPTION_KEY = os.environ.get("MFA_ENCRYPTION_KEY")

    # ------------------------------------------------------------ database ---
    # Primary target is MySQL. DATABASE_URL overrides the assembled URI, which
    # keeps deployment flexible without changing code.
    MYSQL_USER = os.environ.get("MYSQL_USER", "mfa_user")
    MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
    MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
    MYSQL_PORT = _env_int("MYSQL_PORT", 3306)
    MYSQL_DB = os.environ.get("MYSQL_DB", "mfa_db")

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,   # drop dead connections instead of failing a request
        "pool_recycle": 280,     # stay under MySQL's default wait_timeout
    }

    @property
    def SQLALCHEMY_DATABASE_URI(self):  # noqa: N802 (Flask config naming)
        explicit = os.environ.get("DATABASE_URL")
        if explicit:
            return explicit
        return (
            f"mysql+pymysql://{self.MYSQL_USER}:{self.MYSQL_PASSWORD}"
            f"@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DB}?charset=utf8mb4"
        )

    # ------------------------------------------------------------- session ---
    SESSION_COOKIE_NAME = "mfa_session"
    SESSION_COOKIE_HTTPONLY = True          # JavaScript cannot read the cookie
    SESSION_COOKIE_SAMESITE = "Lax"         # blocks cross-site POST cookie use
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=_env_int("SESSION_LIFETIME_MINUTES", 30)
    )
    SESSION_REFRESH_EACH_REQUEST = True

    # Idle timeout enforced in application code (see app/security/session.py).
    SESSION_IDLE_TIMEOUT_MINUTES = _env_int("SESSION_IDLE_TIMEOUT_MINUTES", 15)

    # ---------------------------------------------------------------- CSRF ---
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = _env_int("WTF_CSRF_TIME_LIMIT", 3600)

    # ----------------------------------------------------------------- MFA ---
    MFA_ISSUER_NAME = os.environ.get("MFA_ISSUER_NAME", "ISBAT MFA Demo")
    # Number of 30-second steps accepted either side of the current step.
    # 1 => accepts previous, current and next step (approx 90 s window).
    TOTP_VALID_WINDOW = _env_int("TOTP_VALID_WINDOW", 1)
    TOTP_INTERVAL = _env_int("TOTP_INTERVAL", 30)
    TOTP_DIGITS = _env_int("TOTP_DIGITS", 6)
    # Lifetime of the half-authenticated "password accepted, awaiting OTP" state.
    MFA_PENDING_TTL_SECONDS = _env_int("MFA_PENDING_TTL_SECONDS", 300)
    MFA_PENDING_MAX_ATTEMPTS = _env_int("MFA_PENDING_MAX_ATTEMPTS", 5)
    RECOVERY_CODE_COUNT = _env_int("RECOVERY_CODE_COUNT", 10)

    # ------------------------------------------------------- account lockout --
    MAX_FAILED_LOGINS = _env_int("MAX_FAILED_LOGINS", 5)
    LOCKOUT_MINUTES = _env_int("LOCKOUT_MINUTES", 15)
    PASSWORD_MIN_LENGTH = _env_int("PASSWORD_MIN_LENGTH", 12)

    # --------------------------------------------------------- reset tokens --
    PASSWORD_RESET_TTL_MINUTES = _env_int("PASSWORD_RESET_TTL_MINUTES", 30)

    # ------------------------------------------------------------ rate limit --
    # These are properties rather than plain class attributes so that they are
    # read when the application is built, not when this module is imported.
    # Class-level os.environ reads happen at import time, which makes the
    # setting impossible to override from a test (or from any caller that sets
    # the environment after import).
    @property
    def RATELIMIT_STORAGE_URI(self):  # noqa: N802
        return os.environ.get("RATELIMIT_STORAGE_URI", "memory://")

    @property
    def RATELIMIT_LOGIN(self):  # noqa: N802
        return os.environ.get("RATELIMIT_LOGIN", "10 per minute")

    @property
    def RATELIMIT_MFA(self):  # noqa: N802
        return os.environ.get("RATELIMIT_MFA", "10 per minute")

    @property
    def RATELIMIT_REGISTER(self):  # noqa: N802
        return os.environ.get("RATELIMIT_REGISTER", "5 per minute")

    @property
    def RATELIMIT_RESET(self):  # noqa: N802
        return os.environ.get("RATELIMIT_RESET", "5 per minute")

    @property
    def RATELIMIT_ENABLED(self):  # noqa: N802
        return _env_bool("RATELIMIT_ENABLED", True)

    # ----------------------------------------------------------- argon2id -----
    # Parameters are deliberately explicit so the report can cite them.
    ARGON2_TIME_COST = _env_int("ARGON2_TIME_COST", 3)
    ARGON2_MEMORY_COST = _env_int("ARGON2_MEMORY_COST", 65536)  # 64 MiB
    ARGON2_PARALLELISM = _env_int("ARGON2_PARALLELISM", 2)
    ARGON2_HASH_LEN = _env_int("ARGON2_HASH_LEN", 32)
    ARGON2_SALT_LEN = _env_int("ARGON2_SALT_LEN", 16)

    PREFERRED_URL_SCHEME = os.environ.get("PREFERRED_URL_SCHEME", "http")


class DevelopmentConfig(Config):
    DEBUG = True
    ENV_NAME = "development"


class TestingConfig(Config):
    """Used by pytest. SQLite in memory keeps the suite fast and hermetic.

    The same code path is also exercised against MySQL via
    MFA_TEST_DATABASE_URL (see tests/conftest.py and docs/TEST_RESULTS.md).
    """

    TESTING = True
    DEBUG = False
    ENV_NAME = "testing"
    WTF_CSRF_ENABLED = False      # forms are posted directly by the test client
    SESSION_COOKIE_SECURE = False
    # Lower Argon2 cost so the suite is not dominated by hashing time.
    ARGON2_TIME_COST = 1
    ARGON2_MEMORY_COST = 8192
    ARGON2_PARALLELISM = 1

    @property
    def SQLALCHEMY_DATABASE_URI(self):  # noqa: N802
        return os.environ.get("MFA_TEST_DATABASE_URL", "sqlite:///:memory:")

    @property
    def RATELIMIT_ENABLED(self):  # noqa: N802
        """
        Off by default, so the ordinary tests are not throttled. The
        rate-limiting tests set the environment variable and build their own
        application, which is why this is read late rather than at import.
        """
        return _env_bool("RATELIMIT_ENABLED", False)


class ProductionConfig(Config):
    DEBUG = False
    ENV_NAME = "production"
    SESSION_COOKIE_SECURE = True  # requires HTTPS
    PREFERRED_URL_SCHEME = "https"


config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}


def get_config(name: str | None = None):
    name = (name or os.environ.get("FLASK_CONFIG") or "development").lower()
    return config_map.get(name, DevelopmentConfig)()
