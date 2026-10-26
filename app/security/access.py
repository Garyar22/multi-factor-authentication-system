"""
Server-side access control decorators.

Every protected route carries one of these. Authorisation is never implied by
a hidden navigation link or a client-side route guard: the check runs on the
server, on every request, before the view body executes.
"""

from functools import wraps

from flask import abort, flash, g, redirect, request, url_for

from . import audit
from .session import current_user, get_pending_authentication


def load_current_user() -> None:
    """``before_request`` hook: make the authenticated user available as g.user."""
    g.user = current_user()
    g.pending_user = None
    if g.user is None:
        pending = get_pending_authentication()
        g.pending_user = pending.user if pending else None


def login_required(view):
    """Require a *fully* authenticated session.

    A user who has only passed the password step is sent to the MFA page, not
    to the requested resource. This is the control that makes an MFA bypass
    impossible for an enrolled account.
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            pending = get_pending_authentication()
            if pending is not None:
                flash("Finish two-step verification to continue.", "warning")
                return redirect(url_for("mfa.verify"))
            audit.record_event(
                audit.ACCESS_DENIED,
                category=audit.CATEGORY_ACCESS,
                outcome=audit.OUTCOME_BLOCKED,
                detail=f"unauthenticated access to {request.path}",
            )
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    """Require a fully authenticated session *and* the admin role."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            # Same treatment as login_required: a half-authenticated user is
            # sent to finish the second factor, not told to start again.
            if get_pending_authentication() is not None:
                flash("Finish two-step verification to continue.", "warning")
                return redirect(url_for("mfa.verify"))
            audit.record_event(
                audit.ACCESS_DENIED,
                category=audit.CATEGORY_ACCESS,
                outcome=audit.OUTCOME_BLOCKED,
                detail=f"unauthenticated access to admin path {request.path}",
            )
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("auth.login", next=request.path))
        if not user.is_admin:
            audit.record_event(
                audit.ACCESS_DENIED,
                category=audit.CATEGORY_ACCESS,
                outcome=audit.OUTCOME_BLOCKED,
                user=user,
                detail=f"non-admin attempted {request.path}",
            )
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def anonymous_required(view):
    """Keep signed-in users away from the login and registration pages."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is not None:
            return redirect(url_for("main.dashboard"))
        return view(*args, **kwargs)

    return wrapped


def pending_required(view):
    """Only reachable in the half-authenticated state (the OTP prompt)."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is not None:
            return redirect(url_for("main.dashboard"))
        pending = get_pending_authentication()
        if pending is None:
            flash("Your verification session expired. Please sign in again.", "warning")
            return redirect(url_for("auth.login"))
        g.pending = pending
        return view(*args, **kwargs)

    return wrapped
