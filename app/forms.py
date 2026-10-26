"""
WTForms definitions. Every form inherits CSRF protection from FlaskForm.

Validation here is server-side. The HTML templates add matching client-side
hints for usability only; nothing trusts them.
"""

from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
)

try:  # WTForms >= 3.3 prefers SelectChoice over plain (value, label) tuples.
    from wtforms.fields.choices import SelectChoice
except ImportError:  # pragma: no cover - older WTForms
    SelectChoice = None


def _choices(*pairs):
    """Build SelectField choices in whichever form this WTForms version wants."""
    if SelectChoice is not None:
        return [SelectChoice(value=value, label=label) for value, label in pairs]
    return list(pairs)
from wtforms.validators import (
    DataRequired,
    Email,
    EqualTo,
    Length,
    Optional,
    Regexp,
)


def email_validator(message: str = "Enter a valid email address."):
    """
    Syntax-only email validation.

    ``check_deliverability`` is disabled deliberately. With it enabled the
    validator performs a live DNS/MX lookup inside the request, which:

    * adds unpredictable latency to registration and password reset,
    * makes the form fail when DNS is slow or unavailable, and
    * leaks the submitted address to a resolver on every keystroke-level retry.

    Syntax checking is what a form can honestly assert; genuine proof that an
    address exists comes from sending mail to it, which is noted as future work
    in docs/LIMITATIONS.md.
    """
    return Email(message=message, check_deliverability=False)


class RegistrationForm(FlaskForm):
    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username is required."),
            Length(min=3, max=64),
            Regexp(
                r"^[A-Za-z0-9_.-]+$",
                message="Use letters, digits, dot, dash or underscore only.",
            ),
        ],
    )
    email = StringField(
        "Email address",
        validators=[DataRequired(), email_validator(), Length(max=255)],
    )
    full_name = StringField("Full name", validators=[Optional(), Length(max=120)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])
    confirm_password = PasswordField(
        "Confirm password",
        validators=[DataRequired(), EqualTo("password", message="Passwords do not match.")],
    )
    accept = BooleanField(
        "I understand this is an academic demonstration system",
        validators=[DataRequired(message="Please acknowledge before continuing.")],
    )
    submit = SubmitField("Create account")


class LoginForm(FlaskForm):
    username = StringField("Username or email", validators=[DataRequired(), Length(max=255)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Sign in")


class TotpForm(FlaskForm):
    code = StringField(
        "Authentication code",
        validators=[
            DataRequired(message="Enter the 6-digit code."),
            Regexp(r"^\s*\d{6}\s*$", message="The code is 6 digits."),
        ],
    )
    submit = SubmitField("Verify")


class RecoveryCodeForm(FlaskForm):
    code = StringField("Recovery code", validators=[DataRequired(), Length(max=24)])
    submit = SubmitField("Use recovery code")


class ReauthForm(FlaskForm):
    """Reauthentication before a sensitive change (disabling MFA, new codes)."""

    password = PasswordField("Current password", validators=[DataRequired(), Length(max=128)])
    submit = SubmitField("Confirm")


class DisableMfaForm(FlaskForm):
    password = PasswordField("Current password", validators=[DataRequired(), Length(max=128)])
    code = StringField(
        "Current authentication code",
        validators=[DataRequired(), Regexp(r"^\s*\d{6}\s*$", message="The code is 6 digits.")],
    )
    confirm = BooleanField(
        "I understand my account will be protected by my password only",
        validators=[DataRequired(message="Please confirm you understand the risk.")],
    )
    submit = SubmitField("Disable two-step verification")


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current password", validators=[DataRequired(), Length(max=128)])
    password = PasswordField("New password", validators=[DataRequired(), Length(max=128)])
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("password", message="Passwords do not match.")],
    )
    submit = SubmitField("Change password")


class ForgotPasswordForm(FlaskForm):
    email = StringField(
        "Email address", validators=[DataRequired(), email_validator(), Length(max=255)]
    )
    submit = SubmitField("Send reset link")


class ResetPasswordForm(FlaskForm):
    password = PasswordField("New password", validators=[DataRequired(), Length(max=128)])
    confirm_password = PasswordField(
        "Confirm new password",
        validators=[DataRequired(), EqualTo("password", message="Passwords do not match.")],
    )
    submit = SubmitField("Set new password")


class ProfileForm(FlaskForm):
    full_name = StringField("Full name", validators=[Optional(), Length(max=120)])
    submit = SubmitField("Save changes")


class AdminUserActionForm(FlaskForm):
    """Used for the activate / deactivate / unlock buttons on the admin page."""

    action = SelectField(
        "Action",
        choices=_choices(
            ("activate", "Activate"),
            ("deactivate", "Deactivate"),
            ("unlock", "Unlock"),
        ),
        validators=[DataRequired()],
    )
    submit = SubmitField("Apply")


class EmptyForm(FlaskForm):
    """CSRF-only form, for POST buttons that carry no other input."""

    submit = SubmitField("Confirm")
