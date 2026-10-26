# Project Evidence Record

**Project:** Multi-Factor Authentication (MFA) System for Securing Web Applications
**Student:** Yahye Ahmed Adan · Bachelor of Networks and Cyber Security
**Institution:** ISBAT University, Kampala, Uganda
**Record compiled:** 23 October 2026

This is the single source of truth for the academic report. Every chapter of
the report should describe the system recorded here, using the same figures,
the same terminology and the same version numbers.

---

## 1. What was built

A working Flask web application providing multi-factor authentication: an
Argon2id-hashed password as the first factor and an RFC 6238 time-based
one-time password as the second, with recovery codes, role-based access
control, a security audit trail and an administrative interface.

**Central verified property:** an account with MFA enabled cannot reach a
protected page on a correct password alone.

---

## 2. Implemented features

### 2.1 Registration and account management

| Feature | Implementation | File |
|---------|---------------|------|
| User registration | Server-validated, unique username and email | `app/auth/routes.py` |
| Password policy | Length, composition, predictability, context checks | `app/security/passwords.py` |
| Argon2id hashing | t=3, m=64 MiB, p=2, 16-byte salt, 32-byte hash | `app/security/passwords.py` |
| Profile management | Display name | `app/main/routes.py` |
| Password change | Requires the current password; rotates the session | `app/main/routes.py` |

### 2.2 Authentication

| Feature | Implementation | File |
|---------|---------------|------|
| Login by username or email | Case-insensitive lookup | `app/auth/routes.py` |
| Generic failure message | Identical for unknown user and wrong password | `app/auth/routes.py` |
| Timing equalisation | Real Argon2 verification against a cached dummy hash | `app/security/passwords.py` |
| Account lockout | 5 failures → 15 minutes, state in the database | `app/models.py`, `app/auth/routes.py` |
| Rate limiting | Per-IP, per-endpoint | `app/extensions.py`, route decorators |
| Logout | Deletes the stored session row | `app/security/session.py` |

### 2.3 Multi-factor authentication

| Feature | Implementation | File |
|---------|---------------|------|
| TOTP generation and verification | PyOTP, 6 digits, 30-second step | `app/security/totp.py` |
| Clock-skew window | ±1 step (about 90 seconds) | `app/security/totp.py` |
| **Replay prevention** | Last accepted counter stored and enforced | `app/security/totp.py`, `app/models.py` |
| QR enrollment | Rendered in-process as a data URI | `app/mfa/qr.py` |
| Manual key entry | Base32 key shown with parameters | `app/templates/mfa/enroll.html` |
| Proof before activation | MFA enabled only after a valid code | `app/mfa/routes.py` |
| **Secrets encrypted at rest** | Fernet; key in the environment | `app/security/crypto.py` |
| Pending authentication state | Server-side, expiring, attempt-capped | `app/models.py`, `app/security/session.py` |
| Disable MFA | Requires password **and** a current code | `app/mfa/routes.py` |

### 2.4 Recovery

| Feature | Implementation | File |
|---------|---------------|------|
| Recovery codes | 10 per enrollment, unambiguous alphabet | `app/security/recovery.py` |
| Hashed storage | Argon2id; plaintext never stored | `app/security/recovery.py` |
| Single use | Marked used, never cleared | `app/security/recovery.py` |
| One-time display | Download, print, confirm | `app/templates/mfa/settings.html` |
| Regeneration | Reauthenticated; invalidates the old set | `app/mfa/routes.py` |
| Password reset | SHA-256 token digest, expiring, single use | `app/auth/routes.py` |
| **Reset does not disable MFA** | Explicitly preserved | `app/auth/routes.py` |

### 2.5 Authorisation and administration

| Feature | Implementation | File |
|---------|---------------|------|
| Role-based access control | `admin` and `user` roles | `app/models.py` |
| Server-side enforcement | Decorators on every protected route | `app/security/access.py` |
| Admin dashboard | Live statistics and hotspots | `app/admin/routes.py` |
| User management | Activate, deactivate, unlock | `app/admin/routes.py` |
| Session revocation on deactivation | All sessions deleted at once | `app/security/server_session.py` |
| Audit log viewer | Filterable and paged | `app/admin/routes.py` |
| Last-admin protection | Cannot deactivate self or the last admin | `app/admin/routes.py` |

### 2.6 Security infrastructure

| Feature | Implementation | File |
|---------|---------------|------|
| Server-side sessions | Database-backed store | `app/security/server_session.py` |
| Session rotation | At every privilege change | `app/security/session.py` |
| Idle timeout | 15 minutes, enforced server-side | `app/security/session.py` |
| CSRF protection | Flask-WTF on every state-changing form | `app/extensions.py`, all forms |
| Security headers | CSP, X-Frame-Options, nosniff, Referrer-Policy, HSTS | `app/__init__.py` |
| Audit logging | Every auth decision, secrets scrubbed | `app/security/audit.py` |
| Error handling | Custom pages, no internals exposed | `app/__init__.py` |

---

## 3. Architecture summary

Five layers: presentation, application, **security**, data, testing. The
security layer is separated so that authentication rules live in one place, are
independently testable, and cannot be bypassed by a route that forgets them.

Full diagrams in [`ARCHITECTURE.md`](ARCHITECTURE.md): layered architecture,
component diagram, context diagram, Level 0 DFD, two Level 1 DFDs, the
authentication sequence diagram, the three-state machine and the request
lifecycle.

---

## 4. Database

Eight tables, third normal form, InnoDB, `utf8mb4`.

| Table | Purpose |
|-------|---------|
| `roles` | Role definitions |
| `users` | Accounts, Argon2id hashes, lockout state |
| `mfa_credentials` | Encrypted TOTP secret, confirmation, replay counter |
| `recovery_codes` | Hashed single-use backup codes |
| `password_reset_tokens` | SHA-256 token digests |
| `pending_authentications` | The half-authenticated state |
| `server_sessions` | Server-side session storage |
| `audit_events` | Security event trail |

ERD and table-by-table detail in [`DATABASE.md`](DATABASE.md). The schema
exported from the live database is in
[`diagrams/schema_mysql.sql`](diagrams/schema_mysql.sql).

---

## 5. Development tools and versions

**Record these exactly in the report.** All were verified in the environment
where the results were produced.

| Component | Version |
|-----------|---------|
| Operating system | Linux 6.18 (x86-64) |
| Python | 3.13.17 |
| Flask | 3.1.3 |
| Werkzeug | 3.1.9 |
| Jinja2 | 3.1.6 |
| SQLAlchemy | 2.1.6 |
| Flask-SQLAlchemy | 3.1.1 |
| Flask-Migrate | 4.1.0 |
| Alembic | 1.20.1 |
| PyMySQL | 1.2.3 |
| Flask-WTF | 1.3.0 |
| WTForms | 3.3.0 |
| argon2-cffi | 25.1.0 |
| PyOTP | 2.10.0 |
| qrcode | 8.2 |
| Pillow | 12.3.0 |
| cryptography | 50.0.1 |
| Flask-Limiter | 4.1.1 |
| python-dotenv | 1.2.3 |
| Gunicorn | 26.2.0 |
| pytest | 9.1.1 |
| pytest-cov | 7.1.0 |
| Bootstrap | 5.3.3 (served locally) |
| Database | MariaDB 10.11.14 (MySQL protocol/dialect) |
| Browser used for testing | Chromium via Playwright |

---

## 6. Security controls and their parameters

| Control | Parameter | Value |
|---------|-----------|-------|
| Password hashing | Algorithm | Argon2id |
| | Time cost | 3 iterations |
| | Memory cost | 65 536 KiB (64 MiB) |
| | Parallelism | 2 lanes |
| | Salt length | 16 bytes |
| | Hash length | 32 bytes |
| | Measured cost | ~120 ms per operation |
| Password policy | Minimum length | 12 characters |
| | Required classes | upper, lower, digit, symbol |
| | Blocklist | mangling-aware |
| TOTP | Algorithm | HMAC-SHA1 (RFC 6238) |
| | Digits | 6 |
| | Time step | 30 seconds |
| | Skew window | ±1 step (~90 s) |
| | Secret length | 160 bits (32 base32 characters) |
| | Replay prevention | stored last-accepted counter |
| Secret encryption | Scheme | Fernet (AES-128-CBC + HMAC-SHA256) |
| | Key location | environment variable |
| Recovery codes | Count | 10 |
| | Format | `XXXXX-XXXXX`, 31-symbol alphabet |
| | Storage | Argon2id hash |
| Lockout | Threshold | 5 failures |
| | Duration | 15 minutes |
| Rate limits | Login | 10/min per IP |
| | MFA | 10/min per IP |
| | Registration | 5/min per IP |
| | Reset | 5/min per IP |
| Sessions | Storage | database |
| | Idle timeout | 15 minutes |
| | Absolute lifetime | 30 minutes |
| | Cookie flags | HttpOnly, SameSite=Lax, Secure in production |
| Pending auth | Lifetime | 300 seconds |
| | Attempt cap | 5 |
| Reset tokens | Lifetime | 30 minutes |
| | Storage | SHA-256 digest |

---

## 7. Test evidence

| Measure | Result |
|---------|--------|
| Automated tests (SQLite) | **219 passed, 0 failed** — 18.87 s |
| Automated tests (MySQL) | **219 passed, 0 failed** — 65.15 s |
| Statement coverage of `app/` | **88 %** (1 533 statements) |
| System test, Gunicorn + MySQL + browser | **54 checks, 54 passed** |
| Defects found and resolved | **7** |
| Acceptance criteria met | **12 of 12** |

### Coverage of security-critical modules

| Module | Coverage |
|--------|---------:|
| `security/crypto.py` | 100 % |
| `security/totp.py` | 100 % |
| `security/recovery.py` | 98 % |
| `security/server_session.py` | 98 % |
| `security/access.py` | 97 % |
| `security/passwords.py` | 94 % |
| `security/audit.py` | 93 % |
| `security/session.py` | 92 % |

### Measured performance

| Metric | Result |
|--------|--------|
| Landing page, median | 5.5 ms |
| Login page, median | 6.8 ms |
| Registration page, median | 5.8 ms |
| Health probe, median | 1.9 ms |
| Argon2id hash, mean | 120.6 ms |
| Argon2id verify, mean | 120.5 ms |
| Enumeration timing difference | 8.7 ms (5.9 %) |

Full detail, including the defects found and fixed, in
[`TEST_RESULTS.md`](TEST_RESULTS.md).

---

## 8. Screenshots

**33 images**, all captured from the running application on 23 October 2026,
listed with their purpose in
[`screenshots/INDEX.md`](screenshots/INDEX.md).

The four that carry the central argument:

| File | Proves |
|------|--------|
| `16-bypass-attempt-blocked.png` | A password alone does not reach a protected page |
| `30-audit-filter-replay-blocked.png` | Replay prevention fired in the live system |
| `22-recovery-code-reuse-refused.png` | Recovery codes are genuinely single-use |
| `19-access-denied-403.png` | Authorisation is enforced server-side |

---

## 9. Project statistics

| Metric | Value |
|--------|-------|
| Python source (`app/`) | 3 561 lines |
| HTML templates | 2 000 lines across 26 files |
| Test code | 2 422 lines |
| Configuration and entry point | 227 lines |
| Python files | 36 |
| Documentation | 12 Markdown documents |
| Screenshots | 33 |
| Database tables | 8 |
| Application routes | 23 |
| Automated tests | 219 |
| Audit event types | 29 |
| Total files | 165 |
| Total size | 6.0 MB |

---

## 10. Known limitations

Recorded in full in [`LIMITATIONS.md`](LIMITATIONS.md). The report must
include these; a claim of complete protection would be false.

| Limitation | Severity |
|------------|----------|
| **TOTP is not phishing-resistant** | High — inherent to TOTP |
| Password reset links displayed rather than emailed | Medium — no mail server |
| In-memory rate limiting is per-process | Medium — configuration fix documented |
| Audit log append-only by convention plus a documented grant | Medium |
| Distributed credential stuffing is detected, not prevented | Medium |
| Deliberate lockout can deny service | Low — inherent to lockout |
| Only one second-factor method | Low |
| No breached-password corpus check | Low |
| CLI test coverage 35 % | Low — commands verified manually |

---

## 11. Deployment record

| Item | Value |
|------|-------|
| Environment | Controlled local deployment |
| Application server | Gunicorn 26.2.0, 2 workers |
| Bind address | 127.0.0.1:8000 |
| Database | MariaDB 10.11.14, database `mfa_db`, account `mfa_user` |
| Schema creation | `flask db upgrade`, revision `a30857d12888` |
| Tables created | 8, plus `alembic_version` |
| Administrator | Created with `flask create-admin`; password prompted, never stored |
| Verified headers | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Cache-Control |
| Verified cookie | `HttpOnly; Path=/; SameSite=Lax`, opaque value |
| Health endpoint | `/healthz` returning `{"status": "ok"}` |

**Not deployed** to a public internet-facing server. No claim is made about
behaviour under real-world load or attack.

---

## 12. Requirement traceability

| Requirement group | IDs | Implemented in | Tested by |
|-------------------|-----|----------------|-----------|
| Registration | FR-01 … FR-07 | `auth/routes.py`, `security/passwords.py` | `test_auth_flow.py`, `test_passwords.py` |
| Authentication | FR-08 … FR-14 | `auth/routes.py`, `security/session.py` | `test_auth_flow.py`, `test_security_controls.py` |
| MFA | FR-15 … FR-23 | `mfa/routes.py`, `security/totp.py`, `security/crypto.py` | `test_mfa_flow.py`, `test_totp.py` |
| Recovery | FR-24 … FR-30 | `security/recovery.py`, `auth/routes.py` | `test_crypto_and_recovery.py`, `test_auth_flow.py` |
| Authorisation | FR-31 … FR-38 | `security/access.py`, `admin/routes.py` | `test_security_controls.py`, `test_models_and_admin.py` |
| Audit | FR-39 … FR-45 | `security/audit.py` | `test_security_controls.py` |
| Non-functional | NFR-01 … NFR-13 | throughout | `TEST_RESULTS.md` §6, §7 |

---

## 13. Declaration

This system was designed, implemented, tested and documented by Yahye Ahmed
Adan as a final-year project for the Bachelor of Networks and Cyber Security at
ISBAT University, Kampala.

All security testing described was performed against this application running
on the author's own machine. **No third-party system was tested, probed or
attacked at any point.**

All test results, performance measurements and screenshots in this record were
produced by executing the system. Where something does not work, or works only
within limits, that is stated rather than omitted.
