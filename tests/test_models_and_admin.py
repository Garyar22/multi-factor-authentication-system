"""Model-level tests and administrative interface tests."""

from datetime import timedelta

import pytest
from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models import AuditEvent, PendingAuthentication, Role, User, utcnow
from tests.conftest import ADMIN_PASSWORD, USER_PASSWORD


class TestModelConstraints:
    def test_username_is_unique_at_the_database_level(self, app, user):
        """Even if application checks were bypassed, the schema must refuse."""
        with app.app_context():
            role = Role.query.filter_by(name="user").first()
            db.session.add(
                User(
                    username="alice",
                    email="other@example.com",
                    password_hash="x",
                    role_id=role.id,
                )
            )
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()

    def test_email_is_unique_at_the_database_level(self, app, user):
        with app.app_context():
            role = Role.query.filter_by(name="user").first()
            db.session.add(
                User(
                    username="otherperson",
                    email="alice@example.com",
                    password_hash="x",
                    role_id=role.id,
                )
            )
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()

    def test_role_is_required(self, app):
        with app.app_context():
            db.session.add(
                User(username="noroleuser", email="norole@example.com", password_hash="x")
            )
            with pytest.raises(IntegrityError):
                db.session.commit()
            db.session.rollback()

    def test_defaults_are_safe(self, app, user):
        """A new account must default to no MFA, active, and the user role."""
        with app.app_context():
            u = db.session.get(User, user)
            assert u.is_active is True
            assert u.mfa_enabled is False
            assert u.failed_login_count == 0
            assert u.locked_until is None
            assert u.is_admin is False

    def test_lock_and_unlock_helpers(self, app, user):
        with app.app_context():
            u = db.session.get(User, user)
            assert u.is_locked() is False
            u.lock_for(15)
            assert u.is_locked() is True
            u.unlock()
            assert u.is_locked() is False
            assert u.failed_login_count == 0

    def test_lock_in_the_past_is_not_a_lock(self, app, user):
        with app.app_context():
            u = db.session.get(User, user)
            u.locked_until = utcnow() - timedelta(minutes=1)
            assert u.is_locked() is False

    def test_cascade_delete_removes_dependent_rows(self, app, mfa_user):
        with app.app_context():
            u = db.session.get(User, mfa_user["id"])
            db.session.delete(u)
            db.session.commit()
            from app.models import MfaCredential, RecoveryCode

            assert MfaCredential.query.filter_by(user_id=mfa_user["id"]).count() == 0
            assert RecoveryCode.query.filter_by(user_id=mfa_user["id"]).count() == 0

    def test_pending_authentication_validity(self, app, user):
        with app.app_context():
            record = PendingAuthentication(
                token="tok-for-testing-only",
                user_id=user,
                expires_at=utcnow() + timedelta(minutes=5),
            )
            db.session.add(record)
            db.session.commit()
            assert record.is_valid() is True

            record.expires_at = utcnow() - timedelta(seconds=1)
            assert record.is_valid() is False

            record.expires_at = utcnow() + timedelta(minutes=5)
            record.consumed_at = utcnow()
            assert record.is_valid() is False

    def test_audit_event_has_no_password_column(self, app):
        """A structural guarantee: there is nowhere to put a password."""
        with app.app_context():
            columns = {c.name for c in AuditEvent.__table__.columns}
        for forbidden in ("password", "password_hash", "otp", "code", "secret", "token"):
            assert forbidden not in columns


class TestAdminInterface:
    def test_dashboard_shows_statistics(self, client, admin, user, login):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        response = client.get("/admin/")
        assert response.status_code == 200
        assert b"Registered users" in response.data
        assert b"MFA adoption" in response.data

    def test_user_list_shows_accounts(self, client, admin, user, login):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        response = client.get("/admin/users")
        assert b"alice" in response.data
        assert b"rootadmin" in response.data

    def test_user_search_filters(self, client, admin, user, login):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        response = client.get("/admin/users?q=alice")
        assert b"alice" in response.data

    def test_user_detail_page(self, client, admin, user, login):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        response = client.get(f"/admin/users/{user}")
        assert response.status_code == 200
        assert b"alice" in response.data

    def test_user_detail_404_for_unknown_id(self, client, admin, login):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        assert client.get("/admin/users/999999").status_code == 404

    def test_deactivate_then_activate(self, client, app, admin, user, login):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)

        client.post(f"/admin/users/{user}/action", data={"action": "deactivate"},
                    follow_redirects=True)
        with app.app_context():
            assert db.session.get(User, user).is_active is False

        client.post(f"/admin/users/{user}/action", data={"action": "activate"},
                    follow_redirects=True)
        with app.app_context():
            assert db.session.get(User, user).is_active is True

    def test_admin_actions_are_audited(self, client, app, admin, user, login):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        client.post(f"/admin/users/{user}/action", data={"action": "deactivate"},
                    follow_redirects=True)
        with app.app_context():
            event = AuditEvent.query.filter_by(
                event_type="admin_account_deactivated"
            ).first()
            assert event is not None
            assert event.user_id == admin          # the ACTING admin is recorded
            assert "alice" in (event.detail or "")

    def test_audit_viewer_lists_and_filters(self, client, app, admin, user, login):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        response = client.get("/admin/audit")
        assert response.status_code == 200
        assert b"login_success" in response.data

        filtered = client.get("/admin/audit?event_type=login_success&outcome=success")
        assert filtered.status_code == 200

    def test_audit_viewer_rejects_unknown_filter_safely(self, client, admin, login):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        response = client.get("/admin/audit?event_type=does_not_exist")
        assert response.status_code == 200
        assert b"No events match" in response.data

    def test_failed_login_hotspots_are_surfaced(self, client, app, admin, user, login):
        for _ in range(4):
            client.post("/auth/login", data={"username": "alice", "password": "Wrong#1234!"})
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        response = client.get("/admin/")
        assert b"most failed sign-ins" in response.data.lower() or b"alice" in response.data

    def test_invalid_action_is_rejected(self, client, app, admin, user, login):
        login(client, "rootadmin", ADMIN_PASSWORD, follow=True)
        client.post(f"/admin/users/{user}/action", data={"action": "delete_everything"},
                    follow_redirects=True)
        with app.app_context():
            assert db.session.get(User, user).is_active is True


class TestProfileAndPasswordChange:
    def test_profile_update(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        client.post("/profile", data={"full_name": "Alice Updated"}, follow_redirects=True)
        with app.app_context():
            assert db.session.get(User, user).full_name == "Alice Updated"

    def test_password_change_requires_the_current_password(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        response = client.post(
            "/security",
            data={
                "current_password": "NotMyPassword#9!",
                "password": "Beledweyne#New42!",
                "confirm_password": "Beledweyne#New42!",
            },
        )
        assert response.status_code == 400
        from app.security.passwords import verify_password

        with app.app_context():
            u = db.session.get(User, user)
            assert verify_password(u.password_hash, USER_PASSWORD) is True

    def test_password_change_enforces_the_policy(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        response = client.post(
            "/security",
            data={
                "current_password": USER_PASSWORD,
                "password": "weak",
                "confirm_password": "weak",
            },
        )
        assert response.status_code == 400

    def test_successful_password_change(self, client, app, user, login):
        login(client, "alice", USER_PASSWORD, follow=True)
        client.post(
            "/security",
            data={
                "current_password": USER_PASSWORD,
                "password": "Beledweyne#New42!",
                "confirm_password": "Beledweyne#New42!",
            },
            follow_redirects=True,
        )
        from app.security.passwords import verify_password

        with app.app_context():
            u = db.session.get(User, user)
            assert verify_password(u.password_hash, "Beledweyne#New42!") is True
            assert AuditEvent.query.filter_by(event_type="password_changed").count() >= 1

        client.post("/auth/logout", follow_redirects=True)
        assert client.post(
            "/auth/login", data={"username": "alice", "password": "Beledweyne#New42!"},
            follow_redirects=True,
        ).status_code == 200
