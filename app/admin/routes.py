"""
Administrative interface.

Every route here carries ``@admin_required``, so authorisation is enforced on
the server for each request. Hiding the navigation link is treated as a
usability measure only, never as a security control.
"""

from datetime import timedelta

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for
from sqlalchemy import func

from ..extensions import db
from ..forms import AdminUserActionForm
from ..models import AuditEvent, Role, User, utcnow
from ..security import audit
from ..security.access import admin_required
from ..security.server_session import invalidate_user_sessions

admin_bp = Blueprint("admin", __name__, template_folder="../templates/admin")

PAGE_SIZE = 25


@admin_bp.route("/")
@admin_required
def dashboard():
    """Aggregate security statistics for the last 24 hours and overall."""
    since = utcnow() - timedelta(hours=24)

    total_users = db.session.query(func.count(User.id)).scalar() or 0
    active_users = (
        db.session.query(func.count(User.id)).filter(User.is_active.is_(True)).scalar() or 0
    )
    mfa_users = (
        db.session.query(func.count(User.id)).filter(User.mfa_enabled.is_(True)).scalar() or 0
    )
    locked_users = (
        db.session.query(func.count(User.id))
        .filter(User.locked_until.isnot(None), User.locked_until > utcnow())
        .scalar()
        or 0
    )

    def _count(event_type, since_dt=None):
        query = db.session.query(func.count(AuditEvent.id)).filter(
            AuditEvent.event_type == event_type
        )
        if since_dt is not None:
            query = query.filter(AuditEvent.created_at >= since_dt)
        return query.scalar() or 0

    stats = {
        "total_users": total_users,
        "active_users": active_users,
        "mfa_users": mfa_users,
        "mfa_adoption_pct": round((mfa_users / total_users * 100), 1) if total_users else 0.0,
        "locked_users": locked_users,
        "logins_24h": _count(audit.LOGIN_SUCCESS, since),
        "failed_logins_24h": _count(audit.LOGIN_FAILED, since),
        "mfa_success_24h": _count(audit.MFA_VERIFY_SUCCESS, since),
        "mfa_failed_24h": _count(audit.MFA_VERIFY_FAILED, since),
        "replays_blocked": _count(audit.MFA_VERIFY_REPLAY),
        "recovery_used": _count(audit.MFA_RECOVERY_CODE_USED),
        "access_denied_24h": _count(audit.ACCESS_DENIED, since),
    }

    # Usernames with the most failed logins in the window — the signal an
    # administrator needs to spot a password-spraying attempt.
    hotspots = (
        db.session.query(
            AuditEvent.username_attempted,
            func.count(AuditEvent.id).label("failures"),
            func.max(AuditEvent.created_at).label("last_seen"),
        )
        .filter(
            AuditEvent.event_type == audit.LOGIN_FAILED,
            AuditEvent.created_at >= since,
            AuditEvent.username_attempted.isnot(None),
        )
        .group_by(AuditEvent.username_attempted)
        .order_by(func.count(AuditEvent.id).desc())
        .limit(10)
        .all()
    )

    source_ips = (
        db.session.query(
            AuditEvent.ip_address,
            func.count(AuditEvent.id).label("failures"),
        )
        .filter(
            AuditEvent.event_type == audit.LOGIN_FAILED,
            AuditEvent.created_at >= since,
            AuditEvent.ip_address.isnot(None),
        )
        .group_by(AuditEvent.ip_address)
        .order_by(func.count(AuditEvent.id).desc())
        .limit(10)
        .all()
    )

    recent = AuditEvent.query.order_by(AuditEvent.created_at.desc()).limit(15).all()

    return render_template(
        "admin/dashboard.html",
        stats=stats,
        hotspots=hotspots,
        source_ips=source_ips,
        recent_events=recent,
    )


@admin_bp.route("/users")
@admin_required
def users():
    page = max(request.args.get("page", 1, type=int), 1)
    search = (request.args.get("q") or "").strip()

    query = User.query.join(Role)
    if search:
        # Parameterised by SQLAlchemy — the value never reaches the SQL string.
        like = f"%{search}%"
        query = query.filter(
            db.or_(User.username.like(like), User.email.like(like), User.full_name.like(like))
        )

    pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=PAGE_SIZE, error_out=False
    )

    audit.record_event(
        audit.ADMIN_VIEW_USERS,
        category=audit.CATEGORY_ADMIN,
        user=g.user,
        detail=f"viewed user list page {page}",
    )

    return render_template(
        "admin/users.html",
        pagination=pagination,
        users=pagination.items,
        search=search,
        form=AdminUserActionForm(),
    )


@admin_bp.route("/users/<int:user_id>/action", methods=["POST"])
@admin_required
def user_action(user_id: int):
    """Activate, deactivate or unlock an account."""
    target = db.session.get(User, user_id)
    if target is None:
        abort(404)

    form = AdminUserActionForm()
    if not form.validate_on_submit():
        flash("Invalid request.", "danger")
        return redirect(url_for("admin.users"))

    action = form.action.data

    # An administrator must not be able to lock themselves out of the system,
    # which would leave the deployment with no usable admin account.
    if target.id == g.user.id and action == "deactivate":
        flash("You cannot deactivate your own administrator account.", "danger")
        return redirect(url_for("admin.users"))

    if action == "deactivate":
        if target.is_admin:
            remaining = (
                db.session.query(func.count(User.id))
                .join(Role)
                .filter(Role.name == "admin", User.is_active.is_(True), User.id != target.id)
                .scalar()
                or 0
            )
            if remaining == 0:
                flash("This is the last active administrator and cannot be deactivated.", "danger")
                return redirect(url_for("admin.users"))
        target.is_active = False
        db.session.commit()

        # Revoke the account's live sessions immediately. Without this the user
        # would keep their access until the session expired, which would make
        # "deactivate" useless as an incident-response action.
        revoked = invalidate_user_sessions(target.id)

        audit.record_event(
            audit.ADMIN_ACCOUNT_DEACTIVATED,
            category=audit.CATEGORY_ADMIN,
            user=g.user,
            detail=(
                f"deactivated account id={target.id} username={target.username}; "
                f"{revoked} active session(s) revoked"
            ),
        )
        flash(
            f"Account '{target.username}' deactivated and signed out of "
            f"{revoked} active session(s).",
            "success",
        )

    elif action == "activate":
        target.is_active = True
        db.session.commit()
        audit.record_event(
            audit.ADMIN_ACCOUNT_ACTIVATED,
            category=audit.CATEGORY_ADMIN,
            user=g.user,
            detail=f"activated account id={target.id} username={target.username}",
        )
        flash(f"Account '{target.username}' activated.", "success")

    elif action == "unlock":
        target.unlock()
        db.session.commit()
        audit.record_event(
            audit.ADMIN_ACCOUNT_UNLOCKED,
            category=audit.CATEGORY_ADMIN,
            user=g.user,
            detail=f"cleared lockout for id={target.id} username={target.username}",
        )
        flash(f"Lockout cleared for '{target.username}'.", "success")

    else:
        flash("Unknown action.", "danger")

    return redirect(url_for("admin.users", page=request.args.get("page", 1)))


@admin_bp.route("/users/<int:user_id>")
@admin_required
def user_detail(user_id: int):
    target = db.session.get(User, user_id)
    if target is None:
        abort(404)
    events = (
        AuditEvent.query.filter_by(user_id=target.id)
        .order_by(AuditEvent.created_at.desc())
        .limit(50)
        .all()
    )
    return render_template(
        "admin/user_detail.html", target=target, events=events, form=AdminUserActionForm()
    )


@admin_bp.route("/audit")
@admin_required
def audit_log():
    page = max(request.args.get("page", 1, type=int), 1)
    event_type = (request.args.get("event_type") or "").strip()
    outcome = (request.args.get("outcome") or "").strip()
    category = (request.args.get("category") or "").strip()

    query = AuditEvent.query
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    if outcome:
        query = query.filter(AuditEvent.outcome == outcome)
    if category:
        query = query.filter(AuditEvent.category == category)

    pagination = query.order_by(AuditEvent.created_at.desc()).paginate(
        page=page, per_page=PAGE_SIZE, error_out=False
    )

    event_types = [
        row[0]
        for row in db.session.query(AuditEvent.event_type)
        .distinct()
        .order_by(AuditEvent.event_type)
        .all()
    ]

    audit.record_event(
        audit.ADMIN_VIEW_AUDIT,
        category=audit.CATEGORY_ADMIN,
        user=g.user,
        detail=f"viewed audit log page {page}",
    )

    return render_template(
        "admin/audit.html",
        pagination=pagination,
        events=pagination.items,
        event_types=event_types,
        selected={"event_type": event_type, "outcome": outcome, "category": category},
    )
