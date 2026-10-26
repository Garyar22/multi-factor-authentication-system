"""
MFA enrollment, second-factor verification and recovery-code management.

Enrollment is a two-stage process on purpose. Stage one generates a secret and
stores it *unconfirmed*; stage two requires the user to type a working code
before ``mfa_enabled`` is set. Without that proof-of-possession step a user
could lock themselves out by scanning the QR code incorrectly, and the system
would believe their second factor works when it does not.
"""

from flask import (
    Blueprint,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from ..extensions import db, limiter
from ..forms import DisableMfaForm, EmptyForm, ReauthForm, RecoveryCodeForm, TotpForm
from ..models import MfaCredential, utcnow
from ..security import audit
from ..security.access import login_required, pending_required
from ..security.crypto import decrypt_secret, encrypt_secret, try_decrypt_secret
from ..security.passwords import verify_password
from ..security.recovery import consume_recovery_code, generate_recovery_codes
from ..security.session import (
    complete_login,
    consume_pending_authentication,
    register_pending_attempt,
)
from ..security.totp import generate_secret, provisioning_uri, verify_code
from .qr import qr_data_uri

mfa_bp = Blueprint("mfa", __name__, template_folder="../templates/mfa")

# Session key holding the freshly generated recovery codes for one-time display.
SHOW_CODES_KEY = "show_recovery_codes"

GENERIC_CODE_ERROR = (
    "That code is not valid. Open your authenticator app and enter the "
    "current 6-digit code."
)


def _rate_limit(key: str):
    def _inner():
        return current_app.config.get(key, "10 per minute")

    return _inner


# ---------------------------------------------------------------------------
# Step 2 of login: verify the second factor
# ---------------------------------------------------------------------------

@mfa_bp.route("/verify", methods=["GET", "POST"])
@pending_required
@limiter.limit(_rate_limit("RATELIMIT_MFA"), methods=["POST"])
def verify():
    pending = g.pending
    user = pending.user
    form = TotpForm()

    if form.validate_on_submit():
        credential = user.mfa_credential
        if credential is None or not credential.is_confirmed:
            # Defensive: should be unreachable, because login only creates a
            # pending state for confirmed credentials.
            consume_pending_authentication(pending)
            flash("Two-step verification is not configured for this account.", "danger")
            return redirect(url_for("auth.login"))

        secret = try_decrypt_secret(credential.secret_encrypted)
        if secret is None:
            audit.record_event(
                audit.MFA_VERIFY_FAILED,
                category=audit.CATEGORY_MFA,
                outcome=audit.OUTCOME_FAILURE,
                user=user,
                detail="stored secret could not be decrypted",
            )
            flash(
                "Your second factor could not be read. Use a recovery code or "
                "contact the administrator.",
                "danger",
            )
            return render_template("mfa/verify.html", form=form, user=user), 500

        accepted, counter, reason = verify_code(
            secret, form.code.data, last_used_counter=credential.last_used_counter
        )

        if accepted:
            credential.last_used_counter = counter  # burn this time step
            db.session.commit()
            consume_pending_authentication(pending)
            complete_login(user)
            audit.record_event(
                audit.MFA_VERIFY_SUCCESS,
                category=audit.CATEGORY_MFA,
                user=user,
                detail="second factor verified",
            )
            flash("Two-step verification successful.", "success")
            return redirect(url_for("main.dashboard"))

        # Failure path. The user sees one generic message whether the code was
        # wrong, expired or already used, so nothing is learned from the error.
        event = audit.MFA_VERIFY_REPLAY if reason == "replay" else audit.MFA_VERIFY_FAILED
        audit.record_event(
            event,
            category=audit.CATEGORY_MFA,
            outcome=audit.OUTCOME_FAILURE,
            user=user,
            detail=f"reason={reason}, attempt {pending.attempts + 1}",
        )

        if not register_pending_attempt(pending):
            audit.record_event(
                audit.MFA_PENDING_EXPIRED,
                category=audit.CATEGORY_MFA,
                outcome=audit.OUTCOME_BLOCKED,
                user=user,
                detail="too many second-factor attempts; pending state destroyed",
            )
            flash("Too many incorrect codes. Please sign in again.", "danger")
            return redirect(url_for("auth.login"))

        flash(GENERIC_CODE_ERROR, "danger")
        return render_template("mfa/verify.html", form=form, user=user), 401

    status = 400 if form.errors and request.method == "POST" else 200
    return render_template("mfa/verify.html", form=form, user=user), status


@mfa_bp.route("/recovery", methods=["GET", "POST"])
@pending_required
@limiter.limit(_rate_limit("RATELIMIT_MFA"), methods=["POST"])
def recovery():
    """Second-factor fallback using a single-use recovery code."""
    pending = g.pending
    user = pending.user
    form = RecoveryCodeForm()

    if form.validate_on_submit():
        if consume_recovery_code(user, form.code.data):
            db.session.commit()
            consume_pending_authentication(pending)
            complete_login(user)
            remaining = user.unused_recovery_code_count()
            audit.record_event(
                audit.MFA_RECOVERY_CODE_USED,
                category=audit.CATEGORY_MFA,
                user=user,
                detail=f"recovery code consumed; {remaining} remaining",
            )
            flash(
                f"Signed in with a recovery code. {remaining} unused code(s) remain. "
                "Generate a new set from your security settings.",
                "warning",
            )
            return redirect(url_for("mfa.settings"))

        audit.record_event(
            audit.MFA_RECOVERY_CODE_FAILED,
            category=audit.CATEGORY_MFA,
            outcome=audit.OUTCOME_FAILURE,
            user=user,
            detail=f"invalid or already-used recovery code, attempt {pending.attempts + 1}",
        )
        if not register_pending_attempt(pending):
            flash("Too many incorrect codes. Please sign in again.", "danger")
            return redirect(url_for("auth.login"))

        flash("That recovery code is not valid or has already been used.", "danger")
        return render_template("mfa/recovery.html", form=form, user=user), 401

    return render_template("mfa/recovery.html", form=form, user=user)


# ---------------------------------------------------------------------------
# Enrollment (requires a fully authenticated session)
# ---------------------------------------------------------------------------

@mfa_bp.route("/settings")
@login_required
def settings():
    user = g.user
    # Freshly generated codes are *read*, not popped, so the download and
    # print buttons on this page still work. They are cleared when the user
    # downloads them or presses "I have saved these" (see dismiss_codes), and
    # in any case they live only in the server-side session row, never in the
    # browser cookie.
    codes = session.get(SHOW_CODES_KEY)
    return render_template(
        "mfa/settings.html",
        user=user,
        recovery_codes=codes,
        remaining_codes=user.unused_recovery_code_count(),
        form=EmptyForm(),
    )


@mfa_bp.route("/enroll", methods=["GET", "POST"])
@login_required
@limiter.limit(_rate_limit("RATELIMIT_MFA"), methods=["POST"])
def enroll():
    user = g.user

    if user.mfa_enabled and user.mfa_credential and user.mfa_credential.is_confirmed:
        flash("Two-step verification is already enabled on this account.", "info")
        return redirect(url_for("mfa.settings"))

    credential = user.mfa_credential
    form = TotpForm()

    if request.method == "GET" or credential is None:
        # A new, unconfirmed secret is issued each time the page is opened, so
        # an abandoned enrollment leaves nothing usable behind.
        secret = generate_secret()
        if credential is None:
            credential = MfaCredential(
                user_id=user.id, secret_encrypted=encrypt_secret(secret), method="totp"
            )
            db.session.add(credential)
        else:
            credential.secret_encrypted = encrypt_secret(secret)
            credential.confirmed_at = None
            credential.last_used_counter = None
        db.session.commit()
        audit.record_event(
            audit.MFA_ENROLL_STARTED,
            category=audit.CATEGORY_MFA,
            user=user,
            detail="new unconfirmed TOTP secret issued",
        )
    else:
        secret = decrypt_secret(credential.secret_encrypted)

    uri = provisioning_uri(secret, account_name=user.email)

    if form.validate_on_submit():
        accepted, counter, reason = verify_code(
            secret, form.code.data, last_used_counter=None
        )
        if accepted:
            credential.confirmed_at = utcnow()
            credential.last_used_counter = counter
            user.mfa_enabled = True

            codes = generate_recovery_codes(user)
            db.session.commit()

            audit.record_event(
                audit.MFA_ENROLL_COMPLETED,
                category=audit.CATEGORY_MFA,
                user=user,
                detail="TOTP confirmed and enabled",
            )
            audit.record_event(
                audit.MFA_RECOVERY_CODES_GENERATED,
                category=audit.CATEGORY_MFA,
                user=user,
                detail=f"{len(codes)} recovery codes issued",
            )

            session[SHOW_CODES_KEY] = codes  # shown exactly once
            flash(
                "Two-step verification is now enabled. Save your recovery codes "
                "before leaving this page.",
                "success",
            )
            return redirect(url_for("mfa.settings"))

        audit.record_event(
            audit.MFA_ENROLL_FAILED,
            category=audit.CATEGORY_MFA,
            outcome=audit.OUTCOME_FAILURE,
            user=user,
            detail=f"enrollment code rejected (reason={reason})",
        )
        flash(GENERIC_CODE_ERROR, "danger")
        return (
            render_template(
                "mfa/enroll.html",
                form=form,
                secret=secret,
                qr_uri=qr_data_uri(uri),
                issuer=current_app.config["MFA_ISSUER_NAME"],
                user=user,
            ),
            401,
        )

    return render_template(
        "mfa/enroll.html",
        form=form,
        secret=secret,
        qr_uri=qr_data_uri(uri),
        issuer=current_app.config["MFA_ISSUER_NAME"],
        user=user,
    )


@mfa_bp.route("/disable", methods=["GET", "POST"])
@login_required
@limiter.limit(_rate_limit("RATELIMIT_MFA"), methods=["POST"])
def disable():
    """
    Turning MFA off is a sensitive action, so it requires reauthentication with
    *both* the password and a current TOTP code. A hijacked session alone is
    therefore not enough to strip the account's second factor.
    """
    user = g.user
    if not user.mfa_enabled:
        flash("Two-step verification is not currently enabled.", "info")
        return redirect(url_for("mfa.settings"))

    form = DisableMfaForm()

    if form.validate_on_submit():
        credential = user.mfa_credential
        secret = try_decrypt_secret(credential.secret_encrypted) if credential else None

        password_ok = verify_password(user.password_hash, form.password.data)
        code_ok = False
        if secret is not None:
            code_ok, counter, _ = verify_code(
                secret, form.code.data, last_used_counter=credential.last_used_counter
            )
            if code_ok:
                credential.last_used_counter = counter

        if password_ok and code_ok:
            from ..models import RecoveryCode

            RecoveryCode.query.filter_by(user_id=user.id).delete(synchronize_session=False)
            if credential is not None:
                db.session.delete(credential)
            user.mfa_enabled = False
            db.session.commit()

            audit.record_event(
                audit.MFA_DISABLED,
                category=audit.CATEGORY_MFA,
                outcome=audit.OUTCOME_SUCCESS,
                user=user,
                detail="MFA disabled after password and code reauthentication",
            )
            flash(
                "Two-step verification has been disabled. Your account is now "
                "protected by your password only.",
                "warning",
            )
            return redirect(url_for("mfa.settings"))

        audit.record_event(
            audit.MFA_ENROLL_FAILED,
            category=audit.CATEGORY_MFA,
            outcome=audit.OUTCOME_FAILURE,
            user=user,
            detail="failed reauthentication while attempting to disable MFA",
        )
        db.session.commit()
        flash("Password or authentication code was not correct.", "danger")
        return render_template("mfa/disable.html", form=form, user=user), 401

    return render_template("mfa/disable.html", form=form, user=user)


@mfa_bp.route("/recovery-codes/regenerate", methods=["GET", "POST"])
@login_required
@limiter.limit(_rate_limit("RATELIMIT_MFA"), methods=["POST"])
def regenerate_codes():
    """Issue a fresh set of recovery codes, invalidating the old set."""
    user = g.user
    if not user.mfa_enabled:
        flash("Enable two-step verification first.", "info")
        return redirect(url_for("mfa.settings"))

    form = ReauthForm()
    if form.validate_on_submit():
        if not verify_password(user.password_hash, form.password.data):
            audit.record_event(
                audit.MFA_ENROLL_FAILED,
                category=audit.CATEGORY_MFA,
                outcome=audit.OUTCOME_FAILURE,
                user=user,
                detail="failed reauthentication while regenerating recovery codes",
            )
            flash("That password is not correct.", "danger")
            return render_template("mfa/regenerate_codes.html", form=form), 401

        codes = generate_recovery_codes(user)
        db.session.commit()
        audit.record_event(
            audit.MFA_RECOVERY_CODES_GENERATED,
            category=audit.CATEGORY_MFA,
            user=user,
            detail=f"{len(codes)} new recovery codes issued; previous set invalidated",
        )
        session[SHOW_CODES_KEY] = codes
        flash("New recovery codes generated. The previous set no longer works.", "success")
        return redirect(url_for("mfa.settings"))

    return render_template("mfa/regenerate_codes.html", form=form)


@mfa_bp.route("/recovery-codes/dismiss", methods=["POST"])
@login_required
def dismiss_codes():
    """
    Clear the one-time display slot once the user confirms they have saved the
    codes, so the plaintext does not sit in the session row any longer than it
    has to.
    """
    session.pop(SHOW_CODES_KEY, None)
    flash("Recovery codes hidden. They cannot be displayed again.", "info")
    return redirect(url_for("mfa.settings"))


@mfa_bp.route("/recovery-codes/download", methods=["POST"])
@login_required
def download_codes():
    """
    Serve the just-generated codes as a text file.

    Only codes still held in the one-time session slot can be downloaded;
    stored codes are hashes and cannot be recovered, by design.
    """
    from flask import Response

    codes = session.pop(SHOW_CODES_KEY, None)
    if not codes:
        flash(
            "Recovery codes can only be downloaded immediately after they are "
            "generated. Generate a new set if you no longer have them.",
            "warning",
        )
        return redirect(url_for("mfa.settings"))

    user = g.user
    body = [
        "Multi-Factor Authentication System - Recovery Codes",
        f"Account: {user.username} <{user.email}>",
        f"Generated: {utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC",
        "",
        "Each code works once. Store this file somewhere safe and offline.",
        "",
    ]
    body.extend(f"  {index:2d}. {code}" for index, code in enumerate(codes, start=1))
    body.append("")

    return Response(
        "\n".join(body),
        mimetype="text/plain",
        headers={
            "Content-Disposition": "attachment; filename=mfa-recovery-codes.txt",
            "Cache-Control": "no-store",
        },
    )
