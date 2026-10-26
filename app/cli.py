"""
Flask CLI commands for setup and development.

The administrator account is created through ``flask create-admin``, which
*prompts* for a password or reads one from an environment variable. No
administrator password is hard-coded anywhere in this project, and there is no
hidden master password or bypass account.
"""

import os
import secrets

import click
from flask.cli import with_appcontext

from .extensions import db
from .models import Role, User, utcnow
from .security.passwords import hash_password, validate_password_strength

DEFAULT_ROLES = [
    ("admin", "Administrator with access to user management and audit records"),
    ("user", "Standard application user"),
]


def register_cli_commands(app):
    app.cli.add_command(init_db_command)
    app.cli.add_command(seed_roles_command)
    app.cli.add_command(create_admin_command)
    app.cli.add_command(seed_demo_command)
    app.cli.add_command(generate_keys_command)
    app.cli.add_command(show_config_command)


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Create all tables directly (development shortcut; prefer migrations)."""
    db.create_all()
    _ensure_roles()
    db.session.commit()
    click.echo("Tables created and roles seeded.")


@click.command("seed-roles")
@with_appcontext
def seed_roles_command():
    """Insert the 'admin' and 'user' roles if they are missing."""
    created = _ensure_roles()
    db.session.commit()
    click.echo(f"Roles ready. {created} created.")


def _ensure_roles() -> int:
    created = 0
    for name, description in DEFAULT_ROLES:
        if Role.query.filter_by(name=name).first() is None:
            db.session.add(Role(name=name, description=description))
            created += 1
    db.session.flush()
    return created


@click.command("create-admin")
@click.option("--username", prompt=True, help="Administrator username.")
@click.option("--email", prompt=True, help="Administrator email address.")
@click.option(
    "--password",
    prompt=False,
    default=None,
    help="Omit to be prompted securely, or set ADMIN_PASSWORD in the environment.",
)
@with_appcontext
def create_admin_command(username, email, password):
    """Create an administrator account. The password is never echoed."""
    _ensure_roles()

    username = username.strip()
    email = email.strip().lower()

    if User.query.filter(
        db.or_(User.username == username, User.email == email)
    ).first() is not None:
        raise click.ClickException("A user with that username or email already exists.")

    password = password or os.environ.get("ADMIN_PASSWORD")
    if not password:
        password = click.prompt(
            "Password", hide_input=True, confirmation_prompt=True
        )

    problems = validate_password_strength(password, username=username, email=email)
    if problems:
        for problem in problems:
            click.echo(f"  - {problem}")
        raise click.ClickException("Password does not meet the policy. Nothing was created.")

    admin_role = Role.query.filter_by(name="admin").first()
    user = User(
        username=username,
        email=email,
        full_name="System Administrator",
        password_hash=hash_password(password),
        role_id=admin_role.id,
        is_active=True,
        password_changed_at=utcnow(),
    )
    db.session.add(user)
    db.session.commit()

    click.echo(f"Administrator '{username}' created.")
    click.echo("Sign in and enable two-step verification on this account immediately.")


@click.command("seed-demo")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
@with_appcontext
def seed_demo_command(yes):
    """
    Create non-privileged demonstration users with random passwords.

    Passwords are generated at run time and printed once, so no credential is
    stored in the repository. Intended for a local demo database only.
    """
    if not yes:
        click.confirm(
            "This inserts demonstration users into the current database. Continue?",
            abort=True,
        )

    _ensure_roles()
    user_role = Role.query.filter_by(name="user").first()

    created = []
    for name in ("demo.user", "demo.student", "demo.staff"):
        if User.query.filter_by(username=name).first() is not None:
            continue
        password = f"{secrets.token_urlsafe(12)}Aa1!"
        db.session.add(
            User(
                username=name,
                email=f"{name}@example.com",
                full_name=name.replace(".", " ").title(),
                password_hash=hash_password(password),
                role_id=user_role.id,
                password_changed_at=utcnow(),
            )
        )
        created.append((name, password))

    db.session.commit()

    if not created:
        click.echo("Demonstration users already exist. Nothing to do.")
        return

    click.echo("\nDemonstration accounts created. These passwords are shown once:\n")
    for name, password in created:
        click.echo(f"  {name:<16} {password}")
    click.echo("\nRecord them now if you need them; they are not stored anywhere.\n")


@click.command("generate-keys")
def generate_keys_command():
    """Print fresh values for SECRET_KEY and MFA_ENCRYPTION_KEY."""
    from cryptography.fernet import Fernet

    click.echo(f"SECRET_KEY={secrets.token_hex(32)}")
    click.echo(f"MFA_ENCRYPTION_KEY={Fernet.generate_key().decode()}")
    click.echo("\nCopy these into your .env file. Never commit .env to version control.")


@click.command("show-config")
@with_appcontext
def show_config_command():
    """Print the effective security configuration, with secrets masked."""
    from flask import current_app

    cfg = current_app.config
    uri = cfg["SQLALCHEMY_DATABASE_URI"]
    # Mask the database password before printing.
    if "@" in uri and "//" in uri:
        head, tail = uri.split("//", 1)
        if "@" in tail:
            creds, host = tail.split("@", 1)
            if ":" in creds:
                user_part = creds.split(":", 1)[0]
                uri = f"{head}//{user_part}:****@{host}"

    rows = [
        ("Environment", cfg.get("ENV_NAME")),
        ("Database", uri),
        ("SECRET_KEY set", "yes" if cfg.get("SECRET_KEY") else "NO"),
        ("MFA_ENCRYPTION_KEY set", "yes" if cfg.get("MFA_ENCRYPTION_KEY") else "NO"),
        ("Session cookie secure", cfg.get("SESSION_COOKIE_SECURE")),
        ("Session cookie httponly", cfg.get("SESSION_COOKIE_HTTPONLY")),
        ("Session cookie samesite", cfg.get("SESSION_COOKIE_SAMESITE")),
        ("Session idle timeout (min)", cfg.get("SESSION_IDLE_TIMEOUT_MINUTES")),
        ("CSRF enabled", cfg.get("WTF_CSRF_ENABLED")),
        ("Rate limiting enabled", cfg.get("RATELIMIT_ENABLED")),
        ("Argon2 time cost", cfg.get("ARGON2_TIME_COST")),
        ("Argon2 memory cost (KiB)", cfg.get("ARGON2_MEMORY_COST")),
        ("Argon2 parallelism", cfg.get("ARGON2_PARALLELISM")),
        ("TOTP digits", cfg.get("TOTP_DIGITS")),
        ("TOTP interval (s)", cfg.get("TOTP_INTERVAL")),
        ("TOTP skew window (steps)", cfg.get("TOTP_VALID_WINDOW")),
        ("Max failed logins", cfg.get("MAX_FAILED_LOGINS")),
        ("Lockout (min)", cfg.get("LOCKOUT_MINUTES")),
        ("Password min length", cfg.get("PASSWORD_MIN_LENGTH")),
        ("Recovery code count", cfg.get("RECOVERY_CODE_COUNT")),
        ("Pending MFA TTL (s)", cfg.get("MFA_PENDING_TTL_SECONDS")),
    ]
    width = max(len(str(k)) for k, _ in rows)
    for key, value in rows:
        click.echo(f"{str(key):<{width}}  {value}")
