"""
Server-side session storage.

Why this exists
---------------
Flask's default session is a *signed client-side cookie*: the whole session
dictionary is serialised into the cookie, signed with ``SECRET_KEY`` and sent
to the browser. The signature means the client cannot *modify* it, but it does
not keep the contents secret — anyone holding the cookie can read every value
in it — and the server has no way to revoke a session, because it holds no
record of one.

That is unacceptable for this project for three reasons:

1. **The project specification requires server-side sessions.** A claim that
   authentication state is held server-side has to be true.
2. **Real logout must invalidate.** With a cookie-only session, "logging out"
   only asks the browser to forget the cookie. A copy captured beforehand keeps
   working until it expires. Here, logout deletes the row, so the cookie
   becomes worthless immediately.
3. **Nothing sensitive should ever ride in the cookie.** The one-time display
   of freshly generated recovery codes needs somewhere to keep them between the
   POST that creates them and the page that shows them. In a cookie-based
   session those plaintext codes would be sent to the browser and sit in its
   cookie jar. Here they stay in the database row and are deleted as soon as
   they are shown and saved.

Design
------
The cookie carries only an opaque, cryptographically random session id. All
state lives in the ``server_sessions`` table. ``rotate()`` issues a brand-new
id and deletes the old row, which is what makes session fixation impossible at
each privilege change (login, second-factor completion, password change).

Expired rows are swept opportunistically, so no external cron job is needed
for a single-server academic deployment.
"""

import json
from datetime import datetime, timedelta, timezone

from flask import current_app
from flask.sessions import SessionInterface, SessionMixin
from itsdangerous import BadSignature, URLSafeSerializer
from werkzeug.datastructures import CallbackDict

from ..extensions import db


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class ServerSessionRecord(db.Model):
    """One row per live session."""

    __tablename__ = "server_sessions"

    sid = db.Column(db.String(64), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    data = db.Column(db.Text, nullable=False, default="{}")
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=_utcnow, onupdate=_utcnow)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    def is_live(self) -> bool:
        return self.expires_at > _utcnow()


class ServerSession(CallbackDict, SessionMixin):
    """Dict-like session whose contents are persisted in the database."""

    def __init__(self, initial=None, sid=None, is_new=False):
        def _on_update(_):
            self.modified = True

        super().__init__(initial or {}, _on_update)
        self.sid = sid
        self.is_new = is_new
        self.modified = False
        self.should_rotate = False
        self.should_destroy = False

    def rotate(self) -> None:
        """Request a fresh session id, discarding the old row, on save."""
        self.should_rotate = True
        self.modified = True

    def destroy(self) -> None:
        """Request deletion of the server-side record on save."""
        self.should_destroy = True
        self.modified = True


class ServerSessionInterface(SessionInterface):
    """
    Flask session interface backed by ``server_sessions``.

    The cookie value is the session id, signed so that a client cannot invent
    ids and probe the table. Signing is belt-and-braces: an unsigned random
    64-character id would already be infeasible to guess.
    """

    session_class = ServerSession
    _sweep_counter = 0
    SWEEP_EVERY = 200  # requests between expired-row sweeps

    def _serializer(self, app) -> URLSafeSerializer:
        return URLSafeSerializer(app.config["SECRET_KEY"], salt="mfa-session-id")

    @staticmethod
    def _new_sid() -> str:
        import secrets

        return secrets.token_urlsafe(32)[:64]

    def _lifetime(self, app) -> timedelta:
        return app.permanent_session_lifetime

    # ------------------------------------------------------------- reading --
    def open_session(self, app, request):
        cookie = request.cookies.get(app.config["SESSION_COOKIE_NAME"])
        if not cookie:
            return self.session_class(sid=self._new_sid(), is_new=True)

        try:
            sid = self._serializer(app).loads(cookie)
        except BadSignature:
            # Tampered or signed with an old SECRET_KEY: start fresh rather
            # than trusting any part of it.
            return self.session_class(sid=self._new_sid(), is_new=True)

        record = db.session.get(ServerSessionRecord, sid)
        if record is None or not record.is_live():
            if record is not None:
                db.session.delete(record)
                db.session.commit()
            return self.session_class(sid=self._new_sid(), is_new=True)

        try:
            data = json.loads(record.data) or {}
        except (ValueError, TypeError):
            data = {}

        return self.session_class(initial=data, sid=sid, is_new=False)

    # ------------------------------------------------------------- writing --
    def save_session(self, app, session, response):
        name = app.config["SESSION_COOKIE_NAME"]
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)

        # Explicit destroy (logout): delete the row and clear the cookie.
        if session.should_destroy:
            if session.sid:
                record = db.session.get(ServerSessionRecord, session.sid)
                if record is not None:
                    db.session.delete(record)
                    db.session.commit()
            response.delete_cookie(name, domain=domain, path=path)
            return

        # An empty session means nothing to store.
        if not session:
            if session.modified and not session.is_new and session.sid:
                record = db.session.get(ServerSessionRecord, session.sid)
                if record is not None:
                    db.session.delete(record)
                    db.session.commit()
                response.delete_cookie(name, domain=domain, path=path)
            return

        if not session.modified:
            return

        old_sid = session.sid
        if session.should_rotate:
            session.sid = self._new_sid()
            session.should_rotate = False
            if old_sid:
                stale = db.session.get(ServerSessionRecord, old_sid)
                if stale is not None:
                    db.session.delete(stale)

        expires_at = _utcnow() + self._lifetime(app)
        payload = json.dumps(dict(session))

        record = db.session.get(ServerSessionRecord, session.sid)
        if record is None:
            record = ServerSessionRecord(sid=session.sid)
            db.session.add(record)

        record.data = payload
        record.expires_at = expires_at
        record.user_id = session.get("auth_user_id")
        from flask import request as flask_request

        record.ip_address = (getattr(flask_request, "remote_addr", None) or "")[:45] or None
        record.user_agent = (flask_request.headers.get("User-Agent") or "")[:255] or None

        db.session.commit()
        self._maybe_sweep()

        response.set_cookie(
            name,
            self._serializer(app).dumps(session.sid),
            expires=self.get_expiration_time(app, session),
            httponly=self.get_cookie_httponly(app),
            secure=self.get_cookie_secure(app),
            samesite=self.get_cookie_samesite(app),
            domain=domain,
            path=path,
        )

    # ------------------------------------------------------------ cleanup ---
    def _maybe_sweep(self) -> None:
        """Delete expired rows every so often, cheaply and without a cron job."""
        type(self)._sweep_counter += 1
        if type(self)._sweep_counter % self.SWEEP_EVERY:
            return
        try:
            ServerSessionRecord.query.filter(
                ServerSessionRecord.expires_at < _utcnow()
            ).delete(synchronize_session=False)
            db.session.commit()
        except Exception:  # pragma: no cover - housekeeping must never break a request
            db.session.rollback()
            current_app.logger.warning("Expired-session sweep failed", exc_info=True)


def invalidate_user_sessions(user_id: int, keep_sid: str | None = None) -> int:
    """
    Delete every stored session for a user.

    Used when an administrator deactivates an account: the user is signed out
    everywhere at once instead of keeping access until their cookie expires.
    """
    query = ServerSessionRecord.query.filter(ServerSessionRecord.user_id == user_id)
    if keep_sid:
        query = query.filter(ServerSessionRecord.sid != keep_sid)
    removed = query.delete(synchronize_session=False)
    db.session.commit()
    return removed
