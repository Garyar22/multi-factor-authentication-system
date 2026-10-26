"""
Registration, login, logout and password-reset routes.

The login view is the single most security-sensitive function in the project,
so the ordering of its checks is deliberate and documented inline.
"""

from datetime import timedelta

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from sqlalchemy import func, or_

from ..extensions import db, limiter
from ..forms import ForgotPasswordForm, LoginForm, RegistrationForm, ResetPasswordForm
from ..models import PasswordResetToken, Role, User, utcnow
from ..security import audit
from ..security.access import anonymous_required
from ..security.crypto import generate_url_token, sha256_hex
from ..security.passwords import (
    dummy_hash,
    hash_password,
    validate_password_strength,
    verify_password,
)
from ..security.session import (
    complete_login,
    logout as clear_session,
    start_pending_authentication,
)

auth_bp = Blueprint("auth", __name__, template_folder="../templates/auth")

# One deliberately generic message for every failed login. Revealing whether
# the username exists would let an attacker enumerate accounts.
GENERIC_LOGIN_ERROR = "Invalid credentials. Please check your details and try again."


def _rate_limit(key: str):
    """Read a limit string from config at request time, so tests can change it."""

    def _inner():
        return current_app.config.get(key, "20 per minute")

    return _inner


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@auth_bp.route("/register", methods=["GET", "POST"])
@anonymous_required
@limiter.limit(_rate_limit("RATELIMIT_REGISTER"), methods=["POST"])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()

        problems = validate_password_strength(
            form.password.data, username=username, email=email
        )

        # Case-insensitive uniqueness check. The database also carries UNIQUE
        # constraints, so a race between two requests still cannot create a
        # duplicate — the second INSERT fails and is handled below.
        existing = User.query.filter(
            or_(
                func.lower(User.username) == username.lower(),
                func.lower(User.email) == email,
            )
        ).first()

        if existing is not None:
            # Registration is one place where a specific message is justified:
            # the user needs to know which field to change, and the same
            # information is already obtainable by trying to register again.
            if existing.username.lower() == username.lower():
                form.username.errors.append("That username is already taken.")
            if existing.email.lower() == email:
                form.email.errors.append("An account with that email already exists.")
            audit.record_event(
                audit.REGISTER_FAILED,
                category=audit.CATEGORY_ACCOUNT,
                outcome=audit.OUTCOME_FAILURE,
                username_attempted=username,
                detail="duplicate username or email",
            )
        elif problems:
            for message in problems:
                form.password.errors.append(message)
        else:
            role = Role.query.filter_by(name="user").first()
            if role is None:
                role = Role(name="user", description="Standard application user")
                db.session.add(role)
                db.session.flush()

            user = User(
                username=username,
                email=email,
                full_name=(form.full_name.data or "").strip() or None,
                password_hash=hash_password(form.password.data),
                role_id=role.id,
                password_changed_at=utcnow(),
            )
            db.session.add(user)
            try:
                db.session.commit()
            except Exception:
                db.session.rollback()
                flash("That username or email is already registered.", "danger")
                return render_template("auth/register.html", form=form), 400

            audit.record_event(
                audit.REGISTER_SUCCESS,
                category=audit.CATEGORY_ACCOUNT,
                user=user,
                username_attempted=username,
                detail="account created",
            )
            flash("Account created. Sign in, then enable two-step verification.", "success")
            return redirect(url_for("auth.login"))

    status = 400 if form.errors and request.method == "POST" else 200
    return render_template("auth/register.html", form=form), status


# ---------------------------------------------------------------------------
# Login — step 1 of 2
# ---------------------------------------------------------------------------

@auth_bp.route("/login", methods=["GET", "POST"])
@anonymous_required
@limiter.limit(_rate_limit("RATELIMIT_LOGIN"), methods=["POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        identifier = form.username.data.strip()
        password = form.password.data

        user = User.query.filter(
            or_(
                func.lower(User.username) == identifier.lower(),
                func.lower(User.email) == identifier.lower(),
            )
        ).first()

        # --- 1. Unknown username ------------------------------------------
        # A dummy verification runs so that the response time for an unknown
        # username resembles that of a known one. Without it, the timing
        # difference alone would reveal which usernames exist.
        if user is None:
            # Verify against a REAL Argon2id hash so that this branch costs the
            # same as a genuine password check. Skipping the work here, or
            # using a malformed hash that the library rejects instantly, would
            # make unknown usernames answer measurably faster and hand an
            # attacker a reliable account-enumeration oracle.
            verify_password(dummy_hash(), password)
            audit.record_event(
                audit.LOGIN_FAILED,
                outcome=audit.OUTCOME_FAILURE,
                username_attempted=identifier,
                detail="unknown username",
            )
            flash(GENERIC_LOGIN_ERROR, "danger")
            return render_template("auth/login.html", form=form), 401

        # --- 2. Locked out -------------------------------------------------
        # Checked before the password so that a brute-force run gains no
        # information from a correct guess made during a lockout.
        if user.is_locked():
            audit.record_event(
                audit.LOGIN_BLOCKED_LOCKED,
                outcome=audit.OUTCOME_BLOCKED,
                user=user,
                username_attempted=identifier,
                detail="account temporarily locked",
            )
            flash(
                "This account is temporarily locked after repeated failed sign-in "
                "attempts. Please try again later.",
                "danger",
            )
            return render_template("auth/login.html", form=form), 403

        # --- 3. Deactivated -------------------------------------------------
        if not user.is_active:
            audit.record_event(
                audit.LOGIN_BLOCKED_INACTIVE,
                outcome=audit.OUTCOME_BLOCKED,
                user=user,
                username_attempted=identifier,
                detail="account deactivated",
            )
            flash(GENERIC_LOGIN_ERROR, "danger")
            return render_template("auth/login.html", form=form), 403

        # --- 4. Password ----------------------------------------------------
        if not verify_password(user.password_hash, password):
            user.failed_login_count = (user.failed_login_count or 0) + 1
            locked_now = False
            if user.failed_login_count >= current_app.config["MAX_FAILED_LOGINS"]:
                user.lock_for(current_app.config["LOCKOUT_MINUTES"])
                locked_now = True
            db.session.commit()

            audit.record_event(
                audit.LOGIN_FAILED,
                outcome=audit.OUTCOME_FAILURE,
                user=user,
                username_attempted=identifier,
                detail=f"wrong password (attempt {user.failed_login_count})",
            )
            if locked_now:
                audit.record_event(
                    audit.ACCOUNT_LOCKED,
                    category=audit.CATEGORY_ACCOUNT,
                    outcome=audit.OUTCOME_BLOCKED,
                    user=user,
                    detail=f"locked for {current_app.config['LOCKOUT_MINUTES']} minutes",
                )
                flash(
                    "This account is temporarily locked after repeated failed "
                    "sign-in attempts. Please try again later.",
                    "danger",
                )
                return render_template("auth/login.html", form=form), 403

            flash(GENERIC_LOGIN_ERROR, "danger")
            return render_template("auth/login.html", form=form), 401

        # --- 5. Password accepted -------------------------------------------
        user.failed_login_count = 0
        db.session.commit()

        if user.mfa_enabled and user.mfa_credential and user.mfa_credential.is_confirmed:
            # Half-authenticated only. No protected resource is reachable from
            # here: the session carries an opaque pending token, not a user id.
            start_pending_authentication(user)
            audit.record_event(
                audit.MFA_STEP_REQUIRED,
                category=audit.CATEGORY_MFA,
                user=user,
                detail="password verified, awaiting second factor",
            )
            next_url = request.args.get("next") or request.form.get("next")
            return redirect(url_for("mfa.verify", next=next_url) if next_url
                            else url_for("mfa.verify"))

        # No MFA enrolled: the password alone completes the login.
        complete_login(user)
        audit.record_event(
            audit.LOGIN_SUCCESS,
            user=user,
            detail="password-only login (MFA not enabled)",
        )
        flash("Signed in. Enable two-step verification to protect your account.", "info")
        return redirect(_safe_next(request.args.get("next")) or url_for("main.dashboard"))

    status = 400 if form.errors and request.method == "POST" else 200
    return render_template("auth/login.html", form=form), status


def _safe_next(target: str | None) -> str | None:
    """
    Only allow same-site relative redirects.

    An open redirect would let a phishing page send the victim through this
    site's trusted domain and out to an attacker-controlled one, so anything
    with a scheme, a host or a backslash is rejected.
    """
    if not target:
        return None
    if target.startswith("//") or "\\" in target or ":" in target.split("/")[0]:
        return None
    if not target.startswith("/"):
        return None
    return target


@auth_bp.route("/logout", methods=["POST"])
def logout():
    from ..security.session import current_user

    user = current_user()
    if user is not None:
        audit.record_event(audit.LOGOUT, user=user, detail="user signed out")
    clear_session()
    flash("You have been signed out.", "success")
    return redirect(url_for("main.index"))


# ---------------------------------------------------------------------------
# Password reset
# ---------------------------------------------------------------------------

@auth_bp.route("/forgot-password", methods=["GET", "POST"])
@anonymous_required
@limiter.limit(_rate_limit("RATELIMIT_RESET"), methods=["POST"])
def forgot_password():
    form = ForgotPasswordForm()
    reset_link = None

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        user = User.query.filter(func.lower(User.email) == email).first()

        if user is not None and user.is_active:
            # Earlier unused tokens are invalidated, so only the newest link works.
            PasswordResetToken.query.filter_by(user_id=user.id, used_at=None).update(
                {"used_at": utcnow()}, synchronize_session=False
            )
            raw_token = generate_url_token(32)
            db.session.add(
                PasswordResetToken(
                    user_id=user.id,
                    token_hash=sha256_hex(raw_token),
                    expires_at=utcnow()
                    + timedelta(minutes=current_app.config["PASSWORD_RESET_TTL_MINUTES"]),
                )
            )
            db.session.commit()

            audit.record_event(
                audit.PASSWORD_RESET_REQUESTED,
                category=audit.CATEGORY_ACCOUNT,
                user=user,
                detail="reset token issued",
            )

            # This demonstration system has no mail server. The link is shown
            # on screen so the flow can be exercised and screenshotted. In a
            # real deployment it would be emailed and never rendered — see
            # docs/LIMITATIONS.md.
            reset_link = url_for("auth.reset_password", token=raw_token, _external=True)
        else:
            audit.record_event(
                audit.PASSWORD_RESET_REQUESTED,
                category=audit.CATEGORY_ACCOUNT,
                outcome=audit.OUTCOME_FAILURE,
                username_attempted=email,
                detail="reset requested for unknown or inactive address",
            )

        # The same message either way, so the page cannot be used to test
        # whether an email address is registered.
        flash(
            "If that email address belongs to an active account, a reset link "
            "has been generated.",
            "info",
        )
        return render_template(
            "auth/forgot_password.html", form=ForgotPasswordForm(), reset_link=reset_link
        )

    return render_template("auth/forgot_password.html", form=form, reset_link=None)


@auth_bp.route("/reset-password/<token>", methods=["GET", "POST"])
@anonymous_required
@limiter.limit(_rate_limit("RATELIMIT_RESET"), methods=["POST"])
def reset_password(token: str):
    record = PasswordResetToken.query.filter_by(token_hash=sha256_hex(token)).first()

    if record is None or not record.is_valid():
        audit.record_event(
            audit.PASSWORD_RESET_INVALID_TOKEN,
            category=audit.CATEGORY_ACCOUNT,
            outcome=audit.OUTCOME_FAILURE,
            user_id=record.user_id if record else None,
            detail="expired, already used or unknown reset token",
        )
        flash("That reset link is invalid or has expired. Please request a new one.", "danger")
        return redirect(url_for("auth.forgot_password"))

    user = record.user
    form = ResetPasswordForm()

    if form.validate_on_submit():
        problems = validate_password_strength(
            form.password.data, username=user.username, email=user.email
        )
        if problems:
            for message in problems:
                form.password.errors.append(message)
        else:
            user.password_hash = hash_password(form.password.data)
            user.password_changed_at = utcnow()
            user.unlock()
            record.used_at = utcnow()  # single use

            # A password reset must NOT silently disable MFA. If it did, the
            # reset flow would become a one-step MFA bypass for anyone who can
            # read the user's email.
            db.session.commit()

            audit.record_event(
                audit.PASSWORD_RESET_COMPLETED,
                category=audit.CATEGORY_ACCOUNT,
                user=user,
                detail="password reset; MFA settings unchanged",
            )
            flash(
                "Your password has been reset. Two-step verification is still "
                "required if you had it enabled.",
                "success",
            )
            return redirect(url_for("auth.login"))

    return render_template("auth/reset_password.html", form=form, token=token)
