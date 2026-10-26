"""
Public landing page and the protected demonstration application.

These routes exist to prove the access-control claims in the project: the
dashboard, profile and the sample protected resource are all reachable only
with a fully authenticated session, and the admin area additionally requires
the admin role.
"""

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from ..extensions import db
from ..forms import ChangePasswordForm, ProfileForm
from ..models import AuditEvent, utcnow
from ..security import audit
from ..security.access import login_required
from ..security.passwords import (
    hash_password,
    validate_password_strength,
    verify_password,
)
from ..security.session import complete_login

main_bp = Blueprint("main", __name__, template_folder="../templates/main")


@main_bp.route("/")
def index():
    return render_template("main/index.html")


@main_bp.route("/dashboard")
@login_required
def dashboard():
    user = g.user
    recent = (
        AuditEvent.query.filter_by(user_id=user.id)
        .order_by(AuditEvent.created_at.desc())
        .limit(10)
        .all()
    )
    return render_template(
        "main/dashboard.html",
        user=user,
        recent_events=recent,
        remaining_codes=user.unused_recovery_code_count(),
    )


@main_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = g.user
    form = ProfileForm(obj=user)

    if form.validate_on_submit():
        user.full_name = (form.full_name.data or "").strip() or None
        db.session.commit()
        flash("Profile updated.", "success")
        return redirect(url_for("main.profile"))

    return render_template("main/profile.html", user=user, form=form)


@main_bp.route("/security", methods=["GET", "POST"])
@login_required
def security_settings():
    """Change password. The session is rotated afterwards."""
    user = g.user
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if not verify_password(user.password_hash, form.current_password.data):
            audit.record_event(
                audit.PASSWORD_CHANGED,
                category=audit.CATEGORY_ACCOUNT,
                outcome=audit.OUTCOME_FAILURE,
                user=user,
                detail="password change rejected: current password incorrect",
            )
            form.current_password.errors.append("That is not your current password.")
        else:
            problems = validate_password_strength(
                form.password.data, username=user.username, email=user.email
            )
            if problems:
                for message in problems:
                    form.password.errors.append(message)
            else:
                user.password_hash = hash_password(form.password.data)
                user.password_changed_at = utcnow()
                db.session.commit()

                audit.record_event(
                    audit.PASSWORD_CHANGED,
                    category=audit.CATEGORY_ACCOUNT,
                    user=user,
                    detail="password changed by user",
                )
                # Rotate the session at this privilege change, so any other
                # copy of the old session identifier stops working.
                complete_login(user)
                flash("Your password has been changed.", "success")
                return redirect(url_for("main.security_settings"))

    status = 400 if form.errors and request.method == "POST" else 200
    return render_template(
        "main/security.html", user=user, form=form, remaining_codes=user.unused_recovery_code_count()
    ), status


@main_bp.route("/resources")
@login_required
def resources():
    """A sample protected resource, used to demonstrate enforced access."""
    documents = [
        {
            "title": "Internal Security Policy (sample)",
            "reference": "SEC-POL-001",
            "classification": "Internal",
            "summary": "Password standards, MFA requirement and incident reporting.",
        },
        {
            "title": "Network Diagram (sample)",
            "reference": "NET-DOC-014",
            "classification": "Confidential",
            "summary": "Campus network segmentation and firewall zones.",
        },
        {
            "title": "Incident Response Runbook (sample)",
            "reference": "IR-RUN-007",
            "classification": "Internal",
            "summary": "Steps for triaging a suspected account compromise.",
        },
    ]
    return render_template("main/resources.html", user=g.user, documents=documents)


@main_bp.route("/healthz")
def healthz():
    """Liveness probe for the deployment. Deliberately reveals nothing."""
    try:
        db.session.execute(db.text("SELECT 1"))
        return {"status": "ok"}, 200
    except Exception:
        return {"status": "degraded"}, 503
