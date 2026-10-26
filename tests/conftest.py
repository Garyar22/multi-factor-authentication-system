"""
Shared pytest fixtures.

By default the suite runs against SQLite in memory, so it is fast and needs no
database server. Setting ``MFA_TEST_DATABASE_URL`` runs the identical suite
against MySQL instead, which is how the MySQL results in docs/TEST_RESULTS.md
were produced:

    MFA_TEST_DATABASE_URL="mysql+pymysql://user:pass@localhost/mfa_test_db" pytest
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app import create_app  # noqa: E402
from app.extensions import db as _db  # noqa: E402
from app.models import MfaCredential, Role, User, utcnow  # noqa: E402
from app.security.crypto import encrypt_secret  # noqa: E402
from app.security.passwords import hash_password  # noqa: E402
from app.security.recovery import generate_recovery_codes  # noqa: E402
from app.security.totp import current_counter, generate_secret  # noqa: E402

# Passwords used throughout the suite. They satisfy the policy and contain no
# part of the usernames they belong to.
USER_PASSWORD = "Harbour#Kismayo48!"
ADMIN_PASSWORD = "Mogadishu#Tower71!"


@pytest.fixture(scope="session")
def _keys():
    """Fixed keys for the session, so encrypted values survive within a run."""
    from cryptography.fernet import Fernet

    os.environ.setdefault("SECRET_KEY", "a" * 64)
    os.environ.setdefault("MFA_ENCRYPTION_KEY", Fernet.generate_key().decode())
    return True


@pytest.fixture()
def app(_keys):
    """A fresh application and schema per test, so tests cannot leak into each other."""
    application = create_app("testing")

    with application.app_context():
        _db.create_all()
        for name, description in (
            ("admin", "Administrator"),
            ("user", "Standard application user"),
        ):
            if Role.query.filter_by(name=name).first() is None:
                _db.session.add(Role(name=name, description=description))
        _db.session.commit()

        yield application

        _db.session.remove()
        _db.drop_all()
        # Dispose the engine so connections are closed rather than left for the
        # garbage collector, which otherwise raises ResourceWarning.
        _db.engine.dispose()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def db(app):
    return _db


def _make_user(username, email, password, role_name="user", **kwargs):
    role = Role.query.filter_by(name=role_name).first()
    user = User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role_id=role.id,
        password_changed_at=utcnow(),
        **kwargs,
    )
    _db.session.add(user)
    _db.session.commit()
    return user


@pytest.fixture()
def user(app):
    """A standard user with MFA switched off."""
    with app.app_context():
        u = _make_user("alice", "alice@example.com", USER_PASSWORD)
        _db.session.refresh(u)
        return u.id


@pytest.fixture()
def admin(app):
    """An administrator with MFA switched off."""
    with app.app_context():
        u = _make_user("rootadmin", "rootadmin@example.com", ADMIN_PASSWORD, role_name="admin")
        return u.id


@pytest.fixture()
def mfa_user(app):
    """
    A user with a confirmed TOTP credential and ten recovery codes.

    Returns a dict with the user id, the plaintext TOTP secret and the
    plaintext recovery codes, so tests can act as the genuine account holder.
    """
    with app.app_context():
        u = _make_user("bob", "bob@example.com", USER_PASSWORD, mfa_enabled=True)
        secret = generate_secret()
        credential = MfaCredential(
            user_id=u.id,
            secret_encrypted=encrypt_secret(secret),
            method="totp",
            confirmed_at=utcnow(),
            last_used_counter=None,
        )
        _db.session.add(credential)
        _db.session.commit()
        codes = generate_recovery_codes(u)
        _db.session.commit()
        return {"id": u.id, "secret": secret, "codes": codes, "password": USER_PASSWORD}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture()
def login():
    """Post the password step. Returns the response without following redirects."""

    def _login(client, username, password, follow=False):
        return client.post(
            "/auth/login",
            data={"username": username, "password": password},
            follow_redirects=follow,
        )

    return _login


@pytest.fixture()
def next_step_code():
    """
    Generate a TOTP code for the *next* time step.

    Replay protection burns the step of each accepted code, so a test that has
    just enrolled must move on a step before signing in — exactly as a real
    user waits for the next code. Using an explicit timestamp keeps the suite
    deterministic instead of sleeping for 30 seconds.
    """

    def _code(app, secret, steps=1):
        from app.security.totp import generate_code

        with app.app_context():
            interval = app.config["TOTP_INTERVAL"]
            return generate_code(secret, at=time.time() + steps * interval)

    return _code


@pytest.fixture()
def counter_now():
    def _counter(app):
        with app.app_context():
            return current_counter()

    return _counter


@pytest.fixture()
def advance_clock(monkeypatch):
    """
    Move the application's view of the clock forward by whole TOTP steps.

    Replay protection burns the time step of every accepted code, so a flow
    that needs a *second* fresh code (signing in, then disabling MFA) cannot
    work inside one 30-second step — by design. A real user simply waits for
    the next code; the suite advances a fake clock instead, so the test stays
    deterministic and does not sleep.

    Both ``app.security.totp`` and the test helper read ``time.time``, so
    patching that one function moves generation and verification together.
    """
    import time as time_module

    state = {"offset": 0.0}
    real_time = time_module.time

    def fake_time():
        return real_time() + state["offset"]

    monkeypatch.setattr(time_module, "time", fake_time)

    def _advance(app, steps=1):
        with app.app_context():
            state["offset"] += steps * app.config["TOTP_INTERVAL"]
        return state["offset"]

    return _advance


@pytest.fixture()
def rate_limited_app(_keys, monkeypatch):
    """
    An application with rate limiting switched on from the moment it is built.

    Flask-Limiter decides whether to set up its storage during ``init_app``, so
    enabling the limit afterwards leaves it without a backend. The limit has to
    be in the configuration before the app is created, which is what this
    fixture arranges.
    """
    monkeypatch.setenv("RATELIMIT_ENABLED", "true")
    monkeypatch.setenv("RATELIMIT_LOGIN", "3 per minute")
    monkeypatch.setenv("RATELIMIT_REGISTER", "2 per minute")
    monkeypatch.setenv("RATELIMIT_MFA", "3 per minute")
    monkeypatch.setenv("RATELIMIT_STORAGE_URI", "memory://")

    application = create_app("testing")

    # Flask-Limiter is a module-level singleton shared by every application
    # built in this process, and its ``enabled`` flag is instance state. An
    # app created earlier with limits off will have switched it off, so it is
    # re-enabled and cleared explicitly here.
    from app.extensions import limiter

    limiter.enabled = True
    try:
        limiter.reset()
    except Exception:
        pass

    with application.app_context():
        _db.create_all()
        for name, description in (("admin", "Administrator"), ("user", "Standard user")):
            if Role.query.filter_by(name=name).first() is None:
                _db.session.add(Role(name=name, description=description))
        _db.session.commit()
        _make_user("alice", "alice@example.com", USER_PASSWORD)

        yield application

        _db.session.remove()
        _db.drop_all()
        _db.engine.dispose()

    # Leave the shared limiter in a clean state for later tests.
    try:
        limiter.reset()
    except Exception:
        pass
    limiter.enabled = False
