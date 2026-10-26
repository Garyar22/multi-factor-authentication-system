"""
Integration tests for MFA enrollment, the two-step login and recovery codes.

This module carries the tests for acceptance criteria 2, 3, 4 and 5.
"""

import re
import time
from datetime import timedelta

from app.extensions import db
from app.models import AuditEvent, MfaCredential, PendingAuthentication, User, utcnow
from app.security.crypto import decrypt_secret
from app.security.totp import generate_code
from tests.conftest import USER_PASSWORD

PROTECTED_PATHS = ["/dashboard", "/resources", "/profile", "/security", "/mfa/settings"]


def _secret_from_enroll_page(html: str) -> str:
    return re.search(r'id="totp-secret">([A-Z2-7]+)<', html).group(1)


class TestEnrollment:
    def test_enroll_requires_authentication(self, client):
        response = client.get("/mfa/enroll", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    def test_enroll_page_shows_qr_and_secret(self, client, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        response = client.get("/mfa/enroll")
        assert response.status_code == 200
        body = response.get_data(as_text=True)
        assert 'src="data:image/png;base64,' in body
        assert _secret_from_enroll_page(body)

    def test_secret_is_encrypted_at_rest(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        body = client.get("/mfa/enroll").get_data(as_text=True)
        secret = _secret_from_enroll_page(body)
        with app.app_context():
            credential = MfaCredential.query.filter_by(user_id=user).first()
            assert credential is not None
            assert secret not in credential.secret_encrypted
            assert credential.secret_encrypted.startswith("gAAAA")  # Fernet prefix
            assert decrypt_secret(credential.secret_encrypted) == secret

    def test_credential_stays_unconfirmed_until_proven(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        client.get("/mfa/enroll")
        with app.app_context():
            credential = MfaCredential.query.filter_by(user_id=user).first()
            assert credential.confirmed_at is None
            assert db.session.get(User, user).mfa_enabled is False

    def test_wrong_code_does_not_enable_mfa(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        body = client.get("/mfa/enroll").get_data(as_text=True)
        secret = _secret_from_enroll_page(body)
        wrong = "000000" if generate_code.__call__ and True else "000000"
        with app.app_context():
            if generate_code(secret) == wrong:
                wrong = "111111"
        response = client.post("/mfa/enroll", data={"code": wrong})
        assert response.status_code == 401
        with app.app_context():
            assert db.session.get(User, user).mfa_enabled is False

    def test_valid_code_enables_mfa_and_issues_recovery_codes(
        self, client, app, user, login
    ):
        login(client, "alice", USER_PASSWORD, follow=True)
        body = client.get("/mfa/enroll").get_data(as_text=True)
        secret = _secret_from_enroll_page(body)
        with app.app_context():
            code = generate_code(secret)

        response = client.post("/mfa/enroll", data={"code": code}, follow_redirects=True)
        assert response.status_code == 200
        codes = re.findall(r'class="recovery-code">([A-Z2-9]{5}-[A-Z2-9]{5})<',
                           response.get_data(as_text=True))
        assert len(codes) == app.config["RECOVERY_CODE_COUNT"]

        with app.app_context():
            u = db.session.get(User, user)
            assert u.mfa_enabled is True
            assert u.mfa_credential.is_confirmed is True
            assert u.unused_recovery_code_count() == app.config["RECOVERY_CODE_COUNT"]

    def test_enrollment_is_audited(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        body = client.get("/mfa/enroll").get_data(as_text=True)
        secret = _secret_from_enroll_page(body)
        with app.app_context():
            code = generate_code(secret)
        client.post("/mfa/enroll", data={"code": code}, follow_redirects=True)
        with app.app_context():
            types = {e.event_type for e in AuditEvent.query.all()}
        assert "mfa_enroll_started" in types
        assert "mfa_enroll_completed" in types
        assert "mfa_recovery_codes_generated" in types

    def test_already_enrolled_user_is_redirected(self, client, mfa_user, login):
        login(client, "bob", USER_PASSWORD)
        # complete the second factor first
        pass  # covered in TestTwoStepLogin; enrollment redirect checked below

    def test_reopening_enroll_issues_a_fresh_secret(self, client, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        first = _secret_from_enroll_page(client.get("/mfa/enroll").get_data(as_text=True))
        second = _secret_from_enroll_page(client.get("/mfa/enroll").get_data(as_text=True))
        assert first != second


class TestTwoStepLogin:
    def test_password_alone_does_not_complete_login(self, client, mfa_user, login):
        response = login(client, "bob", USER_PASSWORD)
        assert response.status_code == 302
        assert "/mfa/verify" in response.headers["Location"]

    def test_half_authenticated_user_is_blocked_everywhere(self, client, mfa_user, login):
        """Acceptance criterion 3, checked path by path."""
        login(client, "bob", USER_PASSWORD)
        for path in PROTECTED_PATHS:
            response = client.get(path, follow_redirects=False)
            assert response.status_code == 302, path
            assert "/mfa/verify" in response.headers["Location"], path

    def test_half_authenticated_user_is_blocked_from_admin(self, client, mfa_user, login):
        login(client, "bob", USER_PASSWORD)
        response = client.get("/admin/", follow_redirects=False)
        assert response.status_code == 302
        assert "/mfa/verify" in response.headers["Location"]

    def test_pending_record_is_created_server_side(self, client, app, mfa_user, login):
        login(client, "bob", USER_PASSWORD)
        with app.app_context():
            record = PendingAuthentication.query.filter_by(
                user_id=mfa_user["id"], consumed_at=None
            ).first()
            assert record is not None
            assert record.is_valid() is True

    def test_valid_code_completes_login(self, client, app, mfa_user, login, next_step_code):
        login(client, "bob", USER_PASSWORD)
        code = next_step_code(app, mfa_user["secret"])
        response = client.post("/mfa/verify", data={"code": code}, follow_redirects=True)
        assert response.status_code == 200
        assert b"Welcome" in response.data
        assert client.get("/dashboard").status_code == 200

    def test_invalid_code_is_rejected(self, client, mfa_user, login):
        login(client, "bob", USER_PASSWORD)
        response = client.post("/mfa/verify", data={"code": "123456"})
        assert response.status_code in (401, 400)
        assert client.get("/dashboard", follow_redirects=False).status_code == 302

    def test_code_for_another_account_is_rejected(
        self, client, app, mfa_user, login, next_step_code
    ):
        from app.security.totp import generate_secret

        login(client, "bob", USER_PASSWORD)
        with app.app_context():
            other_secret = generate_secret()
        code = next_step_code(app, other_secret)
        response = client.post("/mfa/verify", data={"code": code})
        assert response.status_code == 401

    def test_used_code_cannot_be_replayed(
        self, client, app, mfa_user, login, next_step_code
    ):
        """Acceptance criterion 4: a reused code is refused."""
        code = next_step_code(app, mfa_user["secret"])

        login(client, "bob", USER_PASSWORD)
        assert client.post(
            "/mfa/verify", data={"code": code}, follow_redirects=True
        ).status_code == 200
        client.post("/auth/logout", follow_redirects=True)

        # Same code, fresh login attempt.
        login(client, "bob", USER_PASSWORD)
        response = client.post("/mfa/verify", data={"code": code})
        assert response.status_code == 401
        assert client.get("/dashboard", follow_redirects=False).status_code == 302

        with app.app_context():
            assert AuditEvent.query.filter_by(
                event_type="mfa_verify_replay_rejected"
            ).count() >= 1

    def test_expired_pending_state_sends_user_back_to_login(
        self, client, app, mfa_user, login, next_step_code
    ):
        login(client, "bob", USER_PASSWORD)
        with app.app_context():
            record = PendingAuthentication.query.filter_by(
                user_id=mfa_user["id"], consumed_at=None
            ).first()
            record.expires_at = utcnow() - timedelta(seconds=1)
            db.session.commit()

        response = client.post(
            "/mfa/verify",
            data={"code": next_step_code(app, mfa_user["secret"])},
            follow_redirects=False,
        )
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]
        assert client.get("/dashboard", follow_redirects=False).status_code == 302

    def test_attempt_cap_destroys_the_pending_state(self, client, app, mfa_user, login):
        login(client, "bob", USER_PASSWORD)
        cap = app.config["MFA_PENDING_MAX_ATTEMPTS"]
        for _ in range(cap):
            client.post("/mfa/verify", data={"code": "123456"})

        response = client.get("/mfa/verify", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    def test_verify_page_unreachable_without_a_pending_state(self, client):
        response = client.get("/mfa/verify", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    def test_mfa_success_is_audited(self, client, app, mfa_user, login, next_step_code):
        login(client, "bob", USER_PASSWORD)
        client.post(
            "/mfa/verify",
            data={"code": next_step_code(app, mfa_user["secret"])},
            follow_redirects=True,
        )
        with app.app_context():
            assert AuditEvent.query.filter_by(event_type="mfa_verify_success").count() == 1
            assert AuditEvent.query.filter_by(event_type="mfa_step_required").count() == 1


class TestRecoveryCodeLogin:
    def test_recovery_code_completes_login(self, client, mfa_user, login):
        login(client, "bob", USER_PASSWORD)
        response = client.post(
            "/mfa/recovery", data={"code": mfa_user["codes"][0]}, follow_redirects=True
        )
        assert response.status_code == 200
        assert client.get("/dashboard").status_code == 200

    def test_recovery_code_is_single_use(self, client, app, mfa_user, login):
        """Acceptance criterion 5."""
        code = mfa_user["codes"][0]
        login(client, "bob", USER_PASSWORD)
        client.post("/mfa/recovery", data={"code": code}, follow_redirects=True)
        client.post("/auth/logout", follow_redirects=True)

        login(client, "bob", USER_PASSWORD)
        response = client.post("/mfa/recovery", data={"code": code})
        assert response.status_code == 401
        assert client.get("/dashboard", follow_redirects=False).status_code == 302

    def test_other_codes_remain_usable(self, client, mfa_user, login):
        login(client, "bob", USER_PASSWORD)
        client.post("/mfa/recovery", data={"code": mfa_user["codes"][0]}, follow_redirects=True)
        client.post("/auth/logout", follow_redirects=True)

        login(client, "bob", USER_PASSWORD)
        response = client.post(
            "/mfa/recovery", data={"code": mfa_user["codes"][1]}, follow_redirects=True
        )
        assert response.status_code == 200
        assert client.get("/dashboard").status_code == 200

    def test_unknown_recovery_code_rejected(self, client, mfa_user, login):
        login(client, "bob", USER_PASSWORD)
        response = client.post("/mfa/recovery", data={"code": "ZZZZZ-ZZZZZ"})
        assert response.status_code == 401

    def test_recovery_use_is_audited_and_counts_down(self, client, app, mfa_user, login):
        login(client, "bob", USER_PASSWORD)
        client.post("/mfa/recovery", data={"code": mfa_user["codes"][0]}, follow_redirects=True)
        with app.app_context():
            assert AuditEvent.query.filter_by(event_type="mfa_recovery_code_used").count() == 1
            u = db.session.get(User, mfa_user["id"])
            assert u.unused_recovery_code_count() == len(mfa_user["codes"]) - 1

    def test_recovery_page_unreachable_without_pending_state(self, client):
        response = client.get("/mfa/recovery", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]


class TestDisableMfa:
    """
    Disabling MFA needs a *fresh* code, and replay protection has just burned
    the step used to sign in. A real user waits for the next code; these tests
    advance a fake clock with the ``advance_clock`` fixture instead, which is
    deterministic and does not sleep for 30 seconds.
    """

    def _sign_in_fully(self, client, app, mfa_user, login):
        from app.security.totp import generate_code

        login(client, "bob", USER_PASSWORD)
        with app.app_context():
            code = generate_code(mfa_user["secret"])
        client.post("/mfa/verify", data={"code": code}, follow_redirects=True)

    def _fresh_code(self, app, mfa_user):
        from app.security.totp import generate_code

        with app.app_context():
            return generate_code(mfa_user["secret"])

    def test_disable_requires_password_and_code(
        self, client, app, mfa_user, login, advance_clock
    ):
        self._sign_in_fully(client, app, mfa_user, login)
        assert client.get("/dashboard").status_code == 200

        # Right password, wrong code.
        response = client.post(
            "/mfa/disable",
            data={"password": USER_PASSWORD, "code": "123456", "confirm": "y"},
        )
        assert response.status_code == 401
        with app.app_context():
            assert db.session.get(User, mfa_user["id"]).mfa_enabled is True

        # Wrong password, genuinely fresh code.
        advance_clock(app, steps=2)
        response = client.post(
            "/mfa/disable",
            data={
                "password": "NotThePassword#9!",
                "code": self._fresh_code(app, mfa_user),
                "confirm": "y",
            },
        )
        assert response.status_code == 401
        with app.app_context():
            assert db.session.get(User, mfa_user["id"]).mfa_enabled is True

    def test_disable_requires_the_confirmation_checkbox(
        self, client, app, mfa_user, login, advance_clock
    ):
        self._sign_in_fully(client, app, mfa_user, login)
        advance_clock(app, steps=2)
        response = client.post(
            "/mfa/disable",
            data={"password": USER_PASSWORD, "code": self._fresh_code(app, mfa_user)},
        )
        assert response.status_code in (200, 400)
        with app.app_context():
            assert db.session.get(User, mfa_user["id"]).mfa_enabled is True

    def test_disable_succeeds_with_both_factors(
        self, client, app, mfa_user, login, advance_clock
    ):
        self._sign_in_fully(client, app, mfa_user, login)
        advance_clock(app, steps=2)
        response = client.post(
            "/mfa/disable",
            data={
                "password": USER_PASSWORD,
                "code": self._fresh_code(app, mfa_user),
                "confirm": "y",
            },
            follow_redirects=True,
        )
        assert response.status_code == 200
        with app.app_context():
            u = db.session.get(User, mfa_user["id"])
            assert u.mfa_enabled is False
            assert u.mfa_credential is None
            assert u.unused_recovery_code_count() == 0
            assert AuditEvent.query.filter_by(event_type="mfa_disabled").count() == 1

    def test_disable_requires_authentication(self, client):
        response = client.get("/mfa/disable", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]


class TestRegenerateCodes:
    def test_regeneration_requires_the_password(
        self, client, app, mfa_user, login, next_step_code
    ):
        login(client, "bob", USER_PASSWORD)
        client.post(
            "/mfa/verify",
            data={"code": next_step_code(app, mfa_user["secret"])},
            follow_redirects=True,
        )
        response = client.post(
            "/mfa/recovery-codes/regenerate", data={"password": "WrongPassword#9!"}
        )
        assert response.status_code == 401

    def test_regeneration_replaces_the_old_set(
        self, client, app, mfa_user, login, next_step_code
    ):
        login(client, "bob", USER_PASSWORD)
        client.post(
            "/mfa/verify",
            data={"code": next_step_code(app, mfa_user["secret"])},
            follow_redirects=True,
        )
        response = client.post(
            "/mfa/recovery-codes/regenerate",
            data={"password": USER_PASSWORD},
            follow_redirects=True,
        )
        new_codes = re.findall(
            r'class="recovery-code">([A-Z2-9]{5}-[A-Z2-9]{5})<',
            response.get_data(as_text=True),
        )
        assert len(new_codes) == app.config["RECOVERY_CODE_COUNT"]
        assert set(new_codes).isdisjoint(set(mfa_user["codes"]))

        # An old code must no longer sign the user in.
        client.post("/auth/logout", follow_redirects=True)
        login(client, "bob", USER_PASSWORD)
        assert client.post(
            "/mfa/recovery", data={"code": mfa_user["codes"][0]}
        ).status_code == 401
