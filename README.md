# Multi-Factor Authentication (MFA) System for Securing Web Applications

**Final-year project — Bachelor of Networks and Cyber Security**
**Student:** Yahye Ahmed Adan
**Institution:** ISBAT University, Kampala, Uganda
**Version:** 1.0.0 · **Built and verified:** 23 October 2026

---

## 1. What this project is

A working web application that demonstrates how multi-factor authentication
protects a web application. A user signs in with a password, and — if they have
enrolled a second factor — must then supply a time-based one-time password
(TOTP) from an authenticator app before any protected page becomes reachable.

This is a **running system, not a proposal**. Every claim in the documentation
is backed by code that executes, tests that were actually run, and screenshots
captured from the live application. Where something is *not* implemented, or
where a control has limits, that is stated plainly in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) rather than glossed over.

### The central security property

> An account with MFA enabled cannot reach a protected page on a correct
> password alone.

After the password step the server creates a short-lived **pending
authentication** record. The browser receives only an opaque token; it is not a
session. Every protected route refuses a request in that state and redirects to
the verification page. A full session is issued in exactly two places in the
code: a password-only login for an account that has not enrolled MFA, and a
successful second-factor verification.

This was verified end to end against MySQL — see
[`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) and screenshot
`16-bypass-attempt-blocked.png`.

---

## 2. Objectives, and where each one is met

| # | Objective | Where it is addressed |
|---|-----------|----------------------|
| 1 | Study existing authentication systems and their limitations | [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) §2 |
| 2 | Analyse risks of password-only authentication | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) |
| 3 | Design an MFA architecture combining passwords with TOTP | [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) |
| 4 | Develop a web-based MFA system (Python, JS, HTML, CSS, MySQL) | `app/`, `config.py`, `migrations/` |
| 5 | Implement and test security, usability, reliability, performance | [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md), [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) |
| 6 | Deploy in a controlled environment and evaluate | [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md), [`docs/PROJECT_EVIDENCE.md`](docs/PROJECT_EVIDENCE.md) |

---

## 3. Technology stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Backend | Python / Flask | 3.13.17 / 3.1.3 |
| Frontend | HTML5, CSS3, JavaScript, Bootstrap | 5.3.3 (served locally) |
| Database | MySQL (verified on MariaDB 10.11.14) | — |
| ORM / migrations | SQLAlchemy 2.1.6, Flask-SQLAlchemy 3.1.1, Flask-Migrate 4.1.0, Alembic 1.20.1 | — |
| Password hashing | Argon2id via argon2-cffi | 25.1.0 |
| Second factor | TOTP (RFC 6238) via PyOTP | 2.10.0 |
| Secret encryption | Fernet via `cryptography` | 50.0.1 |
| CSRF protection | Flask-WTF | 1.3.0 |
| Rate limiting | Flask-Limiter | 4.1.1 |
| Testing | pytest, pytest-cov | 9.1.1, 7.1.0 |
| Production server | Gunicorn (Linux) / Waitress (Windows) | 26.2.0 |

Exact pinned versions are in [`requirements.txt`](requirements.txt).

---

## 4. Quick start

### Prerequisites

* Python 3.11 or newer (developed on 3.13.17)
* MySQL 8.0 or MariaDB 10.6+ running locally
* An authenticator app on your phone (Google Authenticator, Microsoft
  Authenticator, Authy, FreeOTP, Aegis — any RFC 6238 app)

### Steps

```bash
# 1. Create and activate a virtual environment
python -m venv venv
source venv/bin/activate          # Linux / macOS
venv\Scripts\activate             # Windows

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create the MySQL database and account
mysql -u root -p < scripts/create_database.sql

# 4. Create your configuration file
cp .env.example .env              # Linux / macOS
copy .env.example .env            # Windows

# 5. Generate the two required secrets and paste them into .env
flask --app wsgi generate-keys

# 6. Create the database schema
flask --app wsgi db upgrade

# 7. Seed the roles and create your administrator account
flask --app wsgi seed-roles
flask --app wsgi create-admin --username sysadmin --email you@example.com
#    (you will be prompted for a password; it is never echoed or stored in a file)

# 8. Run it
flask --app wsgi run
```

Open <http://127.0.0.1:5000>.

Full instructions, including production deployment and a troubleshooting
section, are in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md). A step-by-step
Windows walkthrough, written for the defence demonstration, is in
[`SETUP_WINDOWS.md`](SETUP_WINDOWS.md).

> **There is no default administrator password in this project**, and no hidden
> master password or bypass account. The administrator is created by the
> command above, with a password you choose, which must satisfy the same policy
> as every other account.

---

## 5. Project layout

```
mfa-system/
├── app/
│   ├── __init__.py              Application factory, hooks, error handlers
│   ├── extensions.py            Unbound extension instances
│   ├── models.py                SQLAlchemy models (the data layer)
│   ├── forms.py                 WTForms definitions with CSRF
│   ├── cli.py                   flask commands: init-db, create-admin, …
│   ├── auth/routes.py           Registration, login, logout, password reset
│   ├── mfa/
│   │   ├── routes.py            Enrollment, verification, recovery codes
│   │   └── qr.py                In-process QR code rendering
│   ├── main/routes.py           Landing page and protected demo application
│   ├── admin/routes.py          User management, audit viewer, statistics
│   ├── security/                ── the security layer ──
│   │   ├── passwords.py         Argon2id hashing and the password policy
│   │   ├── totp.py              TOTP, clock-skew window, replay prevention
│   │   ├── crypto.py            Fernet encryption of secrets, token hashing
│   │   ├── recovery.py          Single-use recovery codes
│   │   ├── session.py           The three authentication states
│   │   ├── server_session.py    Database-backed session store
│   │   ├── access.py            Server-side authorisation decorators
│   │   └── audit.py             Security audit logging with secret scrubbing
│   ├── templates/               Jinja2 templates (Bootstrap 5)
│   └── static/                  CSS, JavaScript, Bootstrap (served locally)
├── migrations/                  Alembic migration scripts
├── tests/                       219 automated tests
├── docs/                        All project documentation and evidence
│   ├── screenshots/             33 screenshots from the running application
│   └── diagrams/                Architecture, DFD, ERD, use-case diagrams
├── scripts/                     Database creation SQL and helper scripts
├── config.py                    Configuration classes
├── wsgi.py                      Entry point
├── requirements.txt             Pinned dependencies
├── pytest.ini                   Test configuration
└── .env.example                 Configuration template (placeholders only)
```

---

## 6. Security controls implemented

| Control | Implementation | Verified by |
|---------|---------------|-------------|
| Password hashing | Argon2id, t=3, m=64 MiB, p=2, per-user salt | `tests/test_passwords.py` |
| Password policy | Length, composition, blocklist with mangling-aware matching, context check | `tests/test_passwords.py` |
| Second factor | TOTP, 6 digits, 30 s step, ±1 step skew window | `tests/test_totp.py` |
| Replay prevention | Last accepted time step recorded and refused thereafter | `tests/test_totp.py`, `tests/test_mfa_flow.py` |
| Secrets at rest | TOTP seeds Fernet-encrypted; key held outside the database | `tests/test_crypto_and_recovery.py` |
| Recovery codes | 10 single-use codes, Argon2id-hashed, shown once | `tests/test_crypto_and_recovery.py` |
| MFA enforcement | Server-side pending state; no protected route reachable from it | `tests/test_mfa_flow.py` |
| Session management | Database-backed sessions, rotated at every privilege change | `tests/test_security_controls.py` |
| Session revocation | Logout and admin deactivation delete the stored session | `tests/test_security_controls.py` |
| Idle timeout | 15 minutes, enforced server-side | `tests/test_security_controls.py` |
| CSRF | Flask-WTF token on every state-changing request | `tests/test_security_controls.py` |
| Brute force | Per-account lockout plus per-IP rate limiting | `tests/test_auth_flow.py`, `tests/test_security_controls.py` |
| Account enumeration | Identical responses and equalised response time | `tests/test_auth_flow.py`, `tests/test_passwords.py` |
| SQL injection | Parameterised queries throughout (ORM) | `tests/test_security_controls.py` |
| XSS | Jinja2 autoescaping plus a CSP with no `unsafe-inline` | `tests/test_security_controls.py` |
| Open redirect | `next` restricted to same-site relative paths | `tests/test_auth_flow.py` |
| RBAC | `@admin_required` on the server for every admin route | `tests/test_security_controls.py` |
| Audit logging | Every auth decision recorded; secrets scrubbed | `tests/test_security_controls.py` |
| Security headers | CSP, X-Frame-Options, nosniff, Referrer-Policy, HSTS in production | `tests/test_security_controls.py` |

---

## 7. Running the tests

```bash
# Against SQLite in memory (fast, no database server needed)
pytest

# With a coverage report
pytest --cov=app --cov-report=term-missing

# Against MySQL, exercising the same suite on the real target database
MFA_TEST_DATABASE_URL="mysql+pymysql://mfa_user:PASSWORD@localhost/mfa_test_db" pytest
```

**Actual results on 23 October 2026:**

| Run | Tests | Result | Duration |
|-----|-------|--------|----------|
| SQLite in memory | 219 | **219 passed, 0 failed** | 18.9 s |
| MySQL (MariaDB 10.11.14) | 219 | **219 passed, 0 failed** | 65.2 s |
| Statement coverage | — | **88 %** of `app/` | — |

Full output, the test plan, and the defects found and fixed along the way are
in [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md).

---

## 8. Documentation index

| Document | Contents |
|----------|----------|
| [`docs/REQUIREMENTS.md`](docs/REQUIREMENTS.md) | Problem statement, objectives, scope, stakeholders, functional and non-functional requirements, feasibility |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Assets, attackers, STRIDE analysis, risk register, which threats are and are not addressed |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Layered architecture, component diagram, context diagram, Level 0 and Level 1 DFDs, authentication sequence |
| [`docs/DATABASE.md`](docs/DATABASE.md) | ERD, table-by-table schema, relationships, indexes, migration strategy |
| [`docs/USE_CASES.md`](docs/USE_CASES.md) | Use-case diagram and written use cases with main and alternate flows |
| [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md) | Test strategy, environment, 60 planned test cases with measurement procedure |
| [`docs/TEST_RESULTS.md`](docs/TEST_RESULTS.md) | Executed results, defects found and fixed, performance measurements |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | MySQL setup, migrations, development and production deployment, HTTPS, troubleshooting |
| [`docs/USER_MANUAL.md`](docs/USER_MANUAL.md) | End-user guide with screenshots |
| [`docs/ADMIN_GUIDE.md`](docs/ADMIN_GUIDE.md) | Administrator guide: user management, audit log, incident response |
| [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) | Honest statement of what this system does *not* do, and future work |
| [`docs/PROJECT_EVIDENCE.md`](docs/PROJECT_EVIDENCE.md) | The evidence record: features, tools, versions, test results, screenshot inventory |
| [`docs/REPORT_MATERIAL.md`](docs/REPORT_MATERIAL.md) | Chapter-by-chapter material for the five-chapter academic report |
| [`docs/screenshots/INDEX.md`](docs/screenshots/INDEX.md) | Annotated index of all 33 screenshots |

---

## 9. Honest scope statement

TOTP defends against a **compromised password** — credential stuffing, a leaked
password database, a weak or reused password, or a shoulder-surfed login. It is
**not phishing-resistant**: an attacker running a real-time proxy can relay a
code within its validity window. Phishing resistance requires origin-bound
credentials such as WebAuthn/passkeys, which are discussed as future work in
[`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) and are deliberately *not* claimed
here.

This is an academic demonstration system built for assessment. It has not been
through an independent security audit and is not hardened for production use.

---

## 10. Licence and academic declaration

This project was produced by Yahye Ahmed Adan as coursework for the Bachelor of
Networks and Cyber Security at ISBAT University, Kampala. Third-party libraries
remain under their own licences, listed in `requirements.txt`.

All security testing described in this repository was carried out against this
application running on the author's own machine. No third-party system was
tested or attacked.
