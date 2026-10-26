"""
Integration tests for registration, login, lockout and password reset.
"""

from datetime import timedelta

from app.extensions import db
from app.models import AuditEvent, PasswordResetToken, User, utcnow
from app.security.crypto import sha256_hex
from app.security.passwords import verify_password
from tests.conftest import USER_PASSWORD


class TestRegistration:
    def test_page_loads(self, client):
        assert client.get("/auth/register").status_code == 200

    def test_successful_registration_creates_a_hashed_user(self, client, app):
        response = client.post(
            "/auth/register",
            data={
                "username": "newcomer",
                "email": "newcomer@example.com",
                "full_name": "New Comer",
                "password": "Berbera#Sunset44!",
                "confirm_password": "Berbera#Sunset44!",
                "accept": "y",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        with app.app_context():
            created = User.query.filter_by(username="newcomer").first()
            assert created is not None
            assert created.password_hash.startswith("$argon2id$")
            assert "Berbera#Sunset44!" not in created.password_hash
            assert created.role.name == "user"       # never admin by default
            assert created.mfa_enabled is False
            assert created.is_active is True

    def test_duplicate_username_rejected(self, client, app, user):
        response = client.post(
            "/auth/register",
            data={
                "username": "alice",
                "email": "different@example.com",
                "password": "Berbera#Sunset44!",
                "confirm_password": "Berbera#Sunset44!",
                "accept": "y",
            },
        )
        assert response.status_code == 400
        assert b"already taken" in response.data
        with app.app_context():
            assert User.query.filter_by(email="different@example.com").first() is None

    def test_duplicate_email_rejected_case_insensitively(self, client, app, user):
        response = client.post(
            "/auth/register",
            data={
                "username": "anotheruser",
                "email": "ALICE@EXAMPLE.COM",
                "password": "Berbera#Sunset44!",
                "confirm_password": "Berbera#Sunset44!",
                "accept": "y",
            },
        )
        assert response.status_code == 400
        with app.app_context():
            assert User.query.filter_by(username="anotheruser").first() is None

    def test_weak_password_rejected(self, client, app):
        response = client.post(
            "/auth/register",
            data={
                "username": "weakling",
                "email": "weakling@example.com",
                "password": "short",
                "confirm_password": "short",
                "accept": "y",
            },
        )
        assert response.status_code == 400
        with app.app_context():
            assert User.query.filter_by(username="weakling").first() is None

    def test_mismatched_confirmation_rejected(self, client, app):
        response = client.post(
            "/auth/register",
            data={
                "username": "mismatch",
                "email": "mismatch@example.com",
                "password": "Berbera#Sunset44!",
                "confirm_password": "Berbera#Sunset45!",
                "accept": "y",
            },
        )
        assert response.status_code == 400
        with app.app_context():
            assert User.query.filter_by(username="mismatch").first() is None

    def test_invalid_username_characters_rejected(self, client, app):
        response = client.post(
            "/auth/register",
            data={
                "username": "bad user!",
                "email": "baduser@example.com",
                "password": "Berbera#Sunset44!",
                "confirm_password": "Berbera#Sunset44!",
                "accept": "y",
            },
        )
        assert response.status_code == 400

    def test_registration_is_audited(self, client, app):
        client.post(
            "/auth/register",
            data={
                "username": "audited",
                "email": "audited@example.com",
                "password": "Berbera#Sunset44!",
                "confirm_password": "Berbera#Sunset44!",
                "accept": "y",
            },
        )
        with app.app_context():
            assert AuditEvent.query.filter_by(event_type="register_success").count() == 1


class TestLogin:
    def test_page_loads(self, client):
        assert client.get("/auth/login").status_code == 200

    def test_correct_password_without_mfa_signs_in(self, client, user, login):
        response = login(client, "alice", USER_PASSWORD, follow=True)
        assert response.status_code == 200
        assert b"Welcome" in response.data

    def test_login_by_email_works(self, client, user, login):
        response = login(client, "alice@example.com", USER_PASSWORD, follow=True)
        assert response.status_code == 200
        assert b"Welcome" in response.data

    def test_wrong_password_rejected(self, client, user, login):
        response = login(client, "alice", "WrongPassword#99!")
        assert response.status_code == 401

    def test_unknown_user_and_wrong_password_look_identical(self, client, user, login):
        """
        User enumeration check: the body shown for an unknown username must be
        the same as for a known username with a wrong password.
        """
        unknown = login(client, "ghostuser", "WrongPassword#99!")
        known = login(client, "alice", "WrongPassword#99!")
        assert unknown.status_code == known.status_code == 401
        assert b"Invalid credentials" in unknown.data
        assert b"Invalid credentials" in known.data

    def test_deactivated_account_cannot_sign_in(self, client, app, user, login):
        with app.app_context():
            u = db.session.get(User, user)
            u.is_active = False
            db.session.commit()
        response = login(client, "alice", USER_PASSWORD)
        assert response.status_code == 403
        assert b"Invalid credentials" in response.data  # no reason disclosed

    def test_failed_attempts_are_counted(self, client, app, user, login):
        for _ in range(3):
            login(client, "alice", "WrongPassword#99!")
        with app.app_context():
            assert db.session.get(User, user).failed_login_count == 3

    def test_successful_login_resets_the_counter(self, client, app, user, login):
        login(client, "alice", "WrongPassword#99!")
        login(client, "alice", USER_PASSWORD, follow=True)
        with app.app_context():
            assert db.session.get(User, user).failed_login_count == 0

    def test_account_locks_after_the_configured_failures(self, client, app, user, login):
        limit = app.config["MAX_FAILED_LOGINS"]
        for _ in range(limit):
            login(client, "alice", "WrongPassword#99!")
        with app.app_context():
            u = db.session.get(User, user)
            assert u.is_locked() is True

        # Even the CORRECT password must now be refused.
        response = login(client, "alice", USER_PASSWORD)
        assert response.status_code == 403
        assert b"temporarily locked" in response.data

    def test_lockout_is_audited(self, client, app, user, login):
        for _ in range(app.config["MAX_FAILED_LOGINS"]):
            login(client, "alice", "WrongPassword#99!")
        with app.app_context():
            assert AuditEvent.query.filter_by(event_type="account_locked").count() >= 1

    def test_lockout_expires(self, client, app, user, login):
        with app.app_context():
            u = db.session.get(User, user)
            u.lock_for(15)
            u.locked_until = utcnow() - timedelta(minutes=1)  # already elapsed
            db.session.commit()
        response = login(client, "alice", USER_PASSWORD, follow=True)
        assert response.status_code == 200
        assert b"Welcome" in response.data

    def test_logout_requires_post(self, client, user, login):
        """A GET logout would be triggerable by any image tag on another site."""
        login(client, "alice", USER_PASSWORD, follow=True)
        assert client.get("/auth/logout").status_code == 405

    def test_logout_ends_the_session(self, client, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        assert client.get("/dashboard").status_code == 200
        client.post("/auth/logout", follow_redirects=True)
        response = client.get("/dashboard", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]


class TestOpenRedirect:
    def test_absolute_external_next_is_ignored(self, client, user, login):
        response = client.post(
            "/auth/login?next=https://evil.example.net/steal",
            data={"username": "alice", "password": USER_PASSWORD},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "evil.example.net" not in response.headers["Location"]

    def test_protocol_relative_next_is_ignored(self, client, user, login):
        response = client.post(
            "/auth/login?next=//evil.example.net/steal",
            data={"username": "alice", "password": USER_PASSWORD},
            follow_redirects=False,
        )
        assert "evil.example.net" not in response.headers["Location"]

    def test_backslash_next_is_ignored(self, client, user, login):
        response = client.post(
            "/auth/login?next=/\\evil.example.net",
            data={"username": "alice", "password": USER_PASSWORD},
            follow_redirects=False,
        )
        assert "evil.example.net" not in response.headers["Location"]

    def test_relative_next_is_honoured(self, client, user, login):
        response = client.post(
            "/auth/login?next=/resources",
            data={"username": "alice", "password": USER_PASSWORD},
            follow_redirects=False,
        )
        assert response.headers["Location"].endswith("/resources")


class TestPasswordReset:
    def test_page_loads(self, client):
        assert client.get("/auth/forgot-password").status_code == 200

    def test_request_for_unknown_email_looks_the_same(self, client, app, user):
        known = client.post("/auth/forgot-password", data={"email": "alice@example.com"})
        unknown = client.post("/auth/forgot-password", data={"email": "nobody@example.com"})
        assert b"If that email address belongs" in known.data
        assert b"If that email address belongs" in unknown.data

    def test_token_is_stored_only_as_a_hash(self, client, app, user):
        client.post("/auth/forgot-password", data={"email": "alice@example.com"})
        with app.app_context():
            record = PasswordResetToken.query.first()
            assert record is not None
            assert len(record.token_hash) == 64  # sha256 hex

    def test_valid_token_resets_the_password(self, client, app, user):
        import re

        response = client.post(
            "/auth/forgot-password", data={"email": "alice@example.com"}
        )
        token = re.search(rb"/auth/reset-password/([A-Za-z0-9_\-]+)", response.data).group(1)
        token = token.decode()

        response = client.post(
            f"/auth/reset-password/{token}",
            data={"password": "Hargeisa#Dawn77!", "confirm_password": "Hargeisa#Dawn77!"},
            follow_redirects=True,
        )
        assert response.status_code == 200
        with app.app_context():
            u = db.session.get(User, user)
            assert verify_password(u.password_hash, "Hargeisa#Dawn77!") is True
            assert verify_password(u.password_hash, USER_PASSWORD) is False

    def test_token_cannot_be_reused(self, client, app, user):
        import re

        response = client.post("/auth/forgot-password", data={"email": "alice@example.com"})
        token = re.search(
            rb"/auth/reset-password/([A-Za-z0-9_\-]+)", response.data
        ).group(1).decode()

        client.post(
            f"/auth/reset-password/{token}",
            data={"password": "Hargeisa#Dawn77!", "confirm_password": "Hargeisa#Dawn77!"},
            follow_redirects=True,
        )
        second = client.post(
            f"/auth/reset-password/{token}",
            data={"password": "Different#Pass88!", "confirm_password": "Different#Pass88!"},
            follow_redirects=True,
        )
        assert b"invalid or has expired" in second.data
        with app.app_context():
            u = db.session.get(User, user)
            assert verify_password(u.password_hash, "Different#Pass88!") is False

    def test_expired_token_rejected(self, client, app, user):
        with app.app_context():
            u = db.session.get(User, user)
            raw = "expired-token-value-for-testing-only"
            db.session.add(
                PasswordResetToken(
                    user_id=u.id,
                    token_hash=sha256_hex(raw),
                    expires_at=utcnow() - timedelta(minutes=1),
                )
            )
            db.session.commit()
        response = client.get(f"/auth/reset-password/{raw}", follow_redirects=True)
        assert b"invalid or has expired" in response.data

    def test_unknown_token_rejected(self, client):
        response = client.get("/auth/reset-password/not-a-real-token", follow_redirects=True)
        assert b"invalid or has expired" in response.data

    def test_reset_does_not_disable_mfa(self, client, app, mfa_user):
        """
        The crucial one: if a reset silently switched MFA off, anyone who could
        read the user's email would have a one-step MFA bypass.
        """
        import re

        response = client.post("/auth/forgot-password", data={"email": "bob@example.com"})
        token = re.search(
            rb"/auth/reset-password/([A-Za-z0-9_\-]+)", response.data
        ).group(1).decode()

        client.post(
            f"/auth/reset-password/{token}",
            data={"password": "Hargeisa#Dawn77!", "confirm_password": "Hargeisa#Dawn77!"},
            follow_redirects=True,
        )
        with app.app_context():
            u = db.session.get(User, mfa_user["id"])
            assert u.mfa_enabled is True
            assert u.mfa_credential is not None
            assert u.mfa_credential.is_confirmed is True

        # And the second factor is still demanded at the next sign-in.
        response = client.post(
            "/auth/login",
            data={"username": "bob", "password": "Hargeisa#Dawn77!"},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "/mfa/verify" in response.headers["Location"]

    def test_reset_clears_an_existing_lockout(self, client, app, user):
        import re

        with app.app_context():
            u = db.session.get(User, user)
            u.lock_for(15)
            u.failed_login_count = 5
            db.session.commit()

        response = client.post("/auth/forgot-password", data={"email": "alice@example.com"})
        token = re.search(
            rb"/auth/reset-password/([A-Za-z0-9_\-]+)", response.data
        ).group(1).decode()
        client.post(
            f"/auth/reset-password/{token}",
            data={"password": "Hargeisa#Dawn77!", "confirm_password": "Hargeisa#Dawn77!"},
            follow_redirects=True,
        )
        with app.app_context():
            u = db.session.get(User, user)
            assert u.is_locked() is False
            assert u.failed_login_count == 0
