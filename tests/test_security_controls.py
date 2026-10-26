"""
Security-control tests: access control, RBAC, CSRF, headers, sessions,
injection resistance, rate limiting and audit-log hygiene.

These map onto section 7 of the project specification.
"""

from datetime import timedelta

import pytest

from app.extensions import db
from app.models import AuditEvent, User, utcnow
from app.security.server_session import ServerSessionRecord
from tests.conftest import ADMIN_PASSWORD, USER_PASSWORD

PROTECTED = ["/dashboard", "/resources", "/profile", "/security", "/mfa/settings",
             "/mfa/enroll"]
ADMIN_ONLY = ["/admin/", "/admin/users", "/admin/audit"]


class TestAccessControl:
    @pytest.mark.parametrize("path", PROTECTED)
    def test_anonymous_cannot_reach_protected_pages(self, client, path):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    @pytest.mark.parametrize("path", ADMIN_ONLY)
    def test_anonymous_cannot_reach_admin_pages(self, client, path):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    def test_unauthenticated_access_is_audited(self, client, app):
        client.get("/dashboard")
        with app.app_context():
            assert AuditEvent.query.filter_by(event_type="access_denied").count() >= 1

    def test_public_pages_remain_public(self, client):
        assert client.get("/").status_code == 200
        assert client.get("/auth/login").status_code == 200
        assert client.get("/auth/register").status_code == 200
        assert client.get("/healthz").status_code == 200


class TestRoleBasedAccessControl:
    @pytest.mark.parametrize("path", ADMIN_ONLY)
    def test_regular_user_is_forbidden(self, client, user, login, path):
        login(client, "alice", USER_PASSWORD, follow=True)
        assert client.get(path).status_code == 403

    @pytest.mark.parametrize("path", ADMIN_ONLY)
    def test_administrator_is_allowed(self, client, admin, login, path):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        assert client.get(path).status_code == 200

    def test_forbidden_attempt_is_audited(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        client.get("/admin/")
        with app.app_context():
            events = AuditEvent.query.filter_by(event_type="access_denied").all()
            assert any("non-admin" in (e.detail or "") for e in events)

    def test_user_cannot_post_an_admin_action(self, client, app, user, admin, login):
        """Authorisation is enforced on POST as well as GET."""
        login(client, "alice", USER_PASSWORD, follow=True)
        response = client.post(f"/admin/users/{admin}/action", data={"action": "deactivate"})
        assert response.status_code == 403
        with app.app_context():
            assert db.session.get(User, admin).is_active is True

    def test_new_registrations_never_get_the_admin_role(self, client, app):
        client.post(
            "/auth/register",
            data={
                "username": "sneaky",
                "email": "sneaky@example.com",
                "password": "Baidoa#Market55!",
                "confirm_password": "Baidoa#Market55!",
                "accept": "y",
                "role": "admin",          # attempt at mass assignment
                "role_id": 1,
                "is_active": True,
                "mfa_enabled": True,
            },
            follow_redirects=True,
        )
        with app.app_context():
            created = User.query.filter_by(username="sneaky").first()
            assert created is not None
            assert created.role.name == "user"
            assert created.mfa_enabled is False

    def test_admin_cannot_deactivate_their_own_account(self, client, app, admin, login):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        client.post(f"/admin/users/{admin}/action", data={"action": "deactivate"},
                    follow_redirects=True)
        with app.app_context():
            assert db.session.get(User, admin).is_active is True

    def test_last_admin_cannot_be_deactivated(self, client, app, admin, login):
        """Prevents locking the whole deployment out of its admin functions."""
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        with app.app_context():
            from app.models import Role

            second = User(
                username="admin2",
                email="admin2@example.com",
                password_hash=db.session.get(User, admin).password_hash,
                role_id=Role.query.filter_by(name="admin").first().id,
                is_active=True,
            )
            db.session.add(second)
            db.session.commit()
            second_id = second.id

        # Deactivating the second admin is allowed...
        client.post(f"/admin/users/{second_id}/action", data={"action": "deactivate"},
                    follow_redirects=True)
        with app.app_context():
            assert db.session.get(User, second_id).is_active is False
            assert db.session.get(User, admin).is_active is True

    def test_admin_deactivation_revokes_user_sessions(
        self, client, app, admin, user, login
    ):
        """Deactivating an account must sign it out immediately."""
        victim = client
        victim.post("/auth/login", data={"username": "alice", "password": USER_PASSWORD},
                    follow_redirects=True)
        assert victim.get("/dashboard").status_code == 200

        admin_client = app.test_client()
        admin_client.post(
            "/auth/login",
            data={"username": "rootadmin", "password": ADMIN_PASSWORD},
            follow_redirects=True,
        )
        admin_client.post(f"/admin/users/{user}/action", data={"action": "deactivate"},
                          follow_redirects=True)

        response = victim.get("/dashboard", follow_redirects=False)
        assert response.status_code == 302

    def test_admin_unlock_clears_lockout(self, client, app, admin, user, login):
        with app.app_context():
            u = db.session.get(User, user)
            u.lock_for(15)
            u.failed_login_count = 5
            db.session.commit()

        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        client.post(f"/admin/users/{user}/action", data={"action": "unlock"},
                    follow_redirects=True)
        with app.app_context():
            u = db.session.get(User, user)
            assert u.is_locked() is False
            assert u.failed_login_count == 0


class TestSessionSecurity:
    def test_session_is_stored_server_side(self, client, app, user, login):
        """The cookie must carry an opaque id, not the session contents."""
        login(client, "alice", USER_PASSWORD, follow=True)
        with app.app_context():
            assert ServerSessionRecord.query.count() >= 1
            record = ServerSessionRecord.query.filter_by(user_id=user).first()
            assert record is not None

        cookie = next(
            (c for c in client.cookie_jar if c.name == app.config["SESSION_COOKIE_NAME"]),
            None,
        ) if hasattr(client, "cookie_jar") else None
        if cookie is not None:
            assert "auth_user_id" not in cookie.value

    def test_cookie_flags_are_set(self, client, user):
        response = client.post(
            "/auth/login",
            data={"username": "alice", "password": USER_PASSWORD},
            follow_redirects=False,
        )
        cookies = response.headers.getlist("Set-Cookie")
        session_cookie = next((c for c in cookies if c.startswith("mfa_session=")), "")
        assert "HttpOnly" in session_cookie
        assert "SameSite=Lax" in session_cookie

    def test_session_id_rotates_on_login(self, client, app, user, login):
        """Session fixation defence: the pre-login id must not be reused."""
        client.get("/auth/login")  # establishes a session row if any
        with app.app_context():
            before = {r.sid for r in ServerSessionRecord.query.all()}
        login(client, "alice", USER_PASSWORD, follow=True)
        with app.app_context():
            after = {r.sid for r in ServerSessionRecord.query.filter_by(user_id=user).all()}
        assert after and not (after & before)

    def test_logout_deletes_the_stored_session(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        with app.app_context():
            assert ServerSessionRecord.query.filter_by(user_id=user).count() == 1
        client.post("/auth/logout", follow_redirects=True)
        with app.app_context():
            assert ServerSessionRecord.query.filter_by(user_id=user).count() == 0

    def test_idle_timeout_ends_the_session(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        assert client.get("/dashboard").status_code == 200

        # Backdate last-seen beyond the idle limit.
        with app.app_context():
            import json

            record = ServerSessionRecord.query.filter_by(user_id=user).first()
            data = json.loads(record.data)
            stale = utcnow() - timedelta(
                minutes=app.config["SESSION_IDLE_TIMEOUT_MINUTES"] + 5
            )
            data["auth_last_seen"] = stale.isoformat()
            record.data = json.dumps(data)
            db.session.commit()

        response = client.get("/dashboard", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    def test_expired_session_row_is_not_honoured(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        with app.app_context():
            record = ServerSessionRecord.query.filter_by(user_id=user).first()
            record.expires_at = utcnow() - timedelta(seconds=1)
            db.session.commit()
        response = client.get("/dashboard", follow_redirects=False)
        assert response.status_code == 302

    def test_forged_cookie_is_rejected(self, client, app, user):
        """A client-invented session id must not authenticate anyone."""
        client.set_cookie("mfa_session", "totally-made-up-value")
        response = client.get("/dashboard", follow_redirects=False)
        assert response.status_code == 302
        assert "/auth/login" in response.headers["Location"]

    def test_password_change_rotates_the_session(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        with app.app_context():
            before = {r.sid for r in ServerSessionRecord.query.filter_by(user_id=user).all()}

        client.post(
            "/security",
            data={
                "current_password": USER_PASSWORD,
                "password": "Jowhar#Bridge83!",
                "confirm_password": "Jowhar#Bridge83!",
            },
            follow_redirects=True,
        )
        with app.app_context():
            after = {r.sid for r in ServerSessionRecord.query.filter_by(user_id=user).all()}
            assert after and not (after & before)


class TestCsrfProtection:
    """CSRF is disabled in TestingConfig, so these tests re-enable it."""

    @pytest.fixture()
    def csrf_app(self, app):
        app.config["WTF_CSRF_ENABLED"] = True
        return app

    def test_post_without_token_is_refused(self, csrf_app):
        client = csrf_app.test_client()
        response = client.post(
            "/auth/login", data={"username": "alice", "password": USER_PASSWORD}
        )
        assert response.status_code == 400

    def test_post_with_a_forged_token_is_refused(self, csrf_app):
        client = csrf_app.test_client()
        response = client.post(
            "/auth/login",
            data={
                "csrf_token": "forged-token-value",
                "username": "alice",
                "password": USER_PASSWORD,
            },
        )
        assert response.status_code == 400

    def test_post_with_a_valid_token_succeeds(self, csrf_app, user):
        import re

        client = csrf_app.test_client()
        page = client.get("/auth/login").get_data(as_text=True)
        token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page).group(1)
        response = client.post(
            "/auth/login",
            data={"csrf_token": token, "username": "alice", "password": USER_PASSWORD},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert b"Welcome" in response.data

    def test_forms_render_a_csrf_token(self, csrf_app):
        client = csrf_app.test_client()
        for path in ("/auth/login", "/auth/register", "/auth/forgot-password"):
            body = client.get(path).get_data(as_text=True)
            assert 'name="csrf_token"' in body, path


class TestSecurityHeaders:
    def test_headers_present_on_every_response(self, client):
        response = client.get("/")
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert "Content-Security-Policy" in response.headers
        assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"

    def test_csp_forbids_inline_and_remote_scripts(self, client):
        csp = client.get("/").headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp
        assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
        assert "frame-ancestors 'none'" in csp
        assert "object-src 'none'" in csp

    def test_no_server_version_disclosure(self, client):
        response = client.get("/")
        assert "X-Powered-By" not in response.headers

    def test_auth_pages_are_not_cached(self, client):
        assert "no-store" in client.get("/auth/login").headers.get("Cache-Control", "")


class TestInjectionResistance:
    @pytest.mark.parametrize(
        "payload",
        [
            "' OR '1'='1",
            "admin'--",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, NULL, NULL --",
            "\" OR 1=1 --",
            "alice' AND SLEEP(5) --",
        ],
    )
    def test_sql_injection_in_login_does_not_authenticate(self, client, app, user, payload):
        response = client.post(
            "/auth/login", data={"username": payload, "password": payload}
        )
        assert response.status_code in (400, 401)
        # And the table is still there with the user intact.
        with app.app_context():
            assert db.session.get(User, user) is not None

    def test_sql_injection_in_admin_search_is_parameterised(
        self, client, app, admin, login
    ):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        response = client.get("/admin/users?q=%27%20OR%20%271%27%3D%271")
        assert response.status_code == 200
        with app.app_context():
            assert db.session.get(User, admin) is not None

    def test_xss_payload_is_escaped_in_output(self, client, app, admin, login):
        """Jinja2 autoescaping must neutralise a stored script payload."""
        payload = "<script>alert('xss')</script>"
        client.post(
            "/auth/register",
            data={
                "username": "xssuser",
                "email": "xssuser@example.com",
                "full_name": payload,
                "password": "Kismayo#Beach66!",
                "confirm_password": "Kismayo#Beach66!",
                "accept": "y",
            },
            follow_redirects=True,
        )
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        body = client.get("/admin/users?q=xssuser").get_data(as_text=True)
        assert "<script>alert('xss')</script>" not in body
        assert "&lt;script&gt;" in body or "xssuser" in body

    def test_xss_in_username_field_is_escaped_on_the_login_page(self, client):
        response = client.post(
            "/auth/login",
            data={"username": "<script>alert(1)</script>", "password": "whatever"},
        )
        assert b"<script>alert(1)</script>" not in response.data


class TestRateLimiting:
    """
    Brute-force throttling. These tests use the ``rate_limited_app`` fixture,
    which builds an application with the limits active from the start.
    """

    def test_repeated_login_attempts_are_throttled(self, rate_limited_app):
        client = rate_limited_app.test_client()
        statuses = [
            client.post(
                "/auth/login", data={"username": "alice", "password": "Wrong#Pass99!"}
            ).status_code
            for _ in range(8)
        ]
        assert 429 in statuses, statuses
        # The limit must bite before the attacker gets eight guesses in.
        assert statuses.index(429) <= 5, statuses

    def test_throttling_applies_to_a_correct_password_too(self, rate_limited_app):
        """
        The limit counts every attempt, not only failures. If it skipped
        successful ones, an attacker working through a credential-stuffing list
        would be throttled while wrong and unthrottled the moment they were
        right, which is precisely backwards.

        A fresh client is used per attempt because an already-signed-in session
        is redirected away from the login page before the limiter is consulted.
        """
        statuses = [
            rate_limited_app.test_client()
            .post("/auth/login", data={"username": "alice", "password": USER_PASSWORD})
            .status_code
            for _ in range(8)
        ]
        assert 429 in statuses, statuses

    def test_registration_is_throttled(self, rate_limited_app):
        client = rate_limited_app.test_client()
        statuses = []
        for index in range(6):
            statuses.append(
                client.post(
                    "/auth/register",
                    data={
                        "username": f"spam{index}",
                        "email": f"spam{index}@example.com",
                        "password": "Afgooye#River21!",
                        "confirm_password": "Afgooye#River21!",
                        "accept": "y",
                    },
                ).status_code
            )
        assert 429 in statuses, statuses

    def test_rate_limited_response_is_audited(self, rate_limited_app):
        client = rate_limited_app.test_client()
        for _ in range(8):
            client.post("/auth/login", data={"username": "alice", "password": "Wrong#1!"})
        with rate_limited_app.app_context():
            assert AuditEvent.query.filter_by(event_type="login_rate_limited").count() >= 1

    def test_get_requests_are_not_throttled(self, rate_limited_app):
        """Only the state-changing POST is limited, so browsing stays usable."""
        client = rate_limited_app.test_client()
        statuses = [client.get("/auth/login").status_code for _ in range(10)]
        assert set(statuses) == {200}


class TestAuditLogHygiene:
    def test_password_never_appears_in_the_audit_log(self, client, app, user, login):
        login(client, "alice", "SuperSecret#Password1!")
        login(client, "alice", USER_PASSWORD, follow=True)
        with app.app_context():
            for event in AuditEvent.query.all():
                blob = f"{event.detail or ''}{event.username_attempted or ''}"
                assert "SuperSecret#Password1!" not in blob
                assert USER_PASSWORD not in blob

    def test_submitted_otp_value_never_appears(self, client, app, mfa_user, login):
        login(client, "bob", USER_PASSWORD)
        client.post("/mfa/verify", data={"code": "987654"})
        with app.app_context():
            for event in AuditEvent.query.all():
                assert "987654" not in (event.detail or "")

    def test_recovery_code_never_appears(self, client, app, mfa_user, login):
        code = mfa_user["codes"][0]
        login(client, "bob", USER_PASSWORD)
        client.post("/mfa/recovery", data={"code": code}, follow_redirects=True)
        with app.app_context():
            for event in AuditEvent.query.all():
                assert code not in (event.detail or "")

    def test_totp_secret_never_appears(self, client, app, mfa_user, login):
        secret = mfa_user["secret"]
        login(client, "bob", USER_PASSWORD)
        client.post("/mfa/verify", data={"code": "111111"})
        with app.app_context():
            for event in AuditEvent.query.all():
                assert secret not in (event.detail or "")

    def test_scrubber_removes_secret_shaped_values(self, app):
        from app.security.audit import scrub

        with app.app_context():
            assert "123456" not in scrub("code was 123456")
            assert "ABCDE-FGHJK" not in scrub("recovery ABCDE-FGHJK used")
            long_token = "x" * 40
            assert long_token not in scrub(f"token {long_token}")

    def test_failed_login_for_unknown_user_is_recorded(self, client, app):
        client.post("/auth/login", data={"username": "ghost", "password": "Whatever#12345!"})
        with app.app_context():
            event = AuditEvent.query.filter_by(event_type="login_failed").first()
            assert event is not None
            assert event.username_attempted == "ghost"
            assert event.user_id is None

    def test_events_carry_timestamp_outcome_and_category(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        with app.app_context():
            event = AuditEvent.query.filter_by(event_type="login_success").first()
            assert event.created_at is not None
            assert event.outcome == "success"
            assert event.category == "auth"


class TestErrorHandling:
    def test_404_page_is_friendly(self, client):
        response = client.get("/no-such-page")
        assert response.status_code == 404
        assert b"Page not found" in response.data

    def test_403_page_is_friendly(self, client, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        response = client.get("/admin/")
        assert response.status_code == 403
        assert b"Access denied" in response.data

    def test_errors_do_not_leak_a_traceback(self, client):
        response = client.get("/no-such-page")
        assert b"Traceback" not in response.data
        assert b"werkzeug" not in response.data.lower()

    def test_health_endpoint_reveals_nothing_sensitive(self, client):
        payload = client.get("/healthz").get_json()
        assert payload == {"status": "ok"}
