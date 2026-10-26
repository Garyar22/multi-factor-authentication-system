# System Architecture and Data Flow

**Project:** Multi-Factor Authentication (MFA) System for Securing Web Applications
**Student:** Yahye Ahmed Adan · ISBAT University, Kampala
**Phase 2 deliverable** · 23 October 2026

---

## 1. Architectural overview

The system uses a **layered architecture** with the security layer separated
from the application layer. That separation is the point: authentication rules
live in one place, are testable on their own, and cannot be accidentally
bypassed by a route that forgets to apply them — because every protected route
goes through a decorator from that layer.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  1. PRESENTATION LAYER                                                    │
│     Jinja2 templates · Bootstrap 5.3.3 · project CSS · app.js            │
│     Responsive, accessible, no security logic, no secrets                │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │ HTTP request / response
┌────────────────────────────────▼─────────────────────────────────────────┐
│  2. APPLICATION LAYER  (Flask blueprints)                                │
│     auth/  registration, login, logout, password reset                   │
│     mfa/   enrollment, verification, recovery codes                      │
│     main/  landing page, dashboard, profile, protected resources         │
│     admin/ user management, audit viewer, statistics                     │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │ every protected route calls into ↓
┌────────────────────────────────▼─────────────────────────────────────────┐
│  3. SECURITY LAYER  (app/security/)                                      │
│     passwords.py       Argon2id hashing, password policy                 │
│     totp.py            RFC 6238 codes, skew window, replay prevention    │
│     crypto.py          Fernet encryption of secrets, token hashing       │
│     recovery.py        single-use recovery codes                         │
│     session.py         the three authentication states                   │
│     server_session.py  database-backed session store                     │
│     access.py          @login_required, @admin_required, @pending_required│
│     audit.py           event recording with secret scrubbing             │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │ SQLAlchemy ORM (parameterised)
┌────────────────────────────────▼─────────────────────────────────────────┐
│  4. DATA LAYER                                                            │
│     models.py · Alembic migrations · MySQL 8 / MariaDB 10.11             │
│     users · roles · mfa_credentials · recovery_codes                     │
│     password_reset_tokens · pending_authentications                      │
│     server_sessions · audit_events                                       │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  5. TESTING LAYER  (tests/)  —  214 automated tests                      │
│     unit · integration · security · model constraint tests               │
└──────────────────────────────────────────────────────────────────────────┘
```

### Why these boundaries

* **Presentation holds no security logic.** `app.js` carries a password
  strength meter and OTP input helpers, and the file says in its own header
  that none of it is a control — every rule it mirrors is enforced again on the
  server. An attacker who disables JavaScript gains nothing.
* **The application layer makes no security decisions itself.** Routes call
  into the security layer and act on the answer.
* **The security layer is independently testable.** `tests/test_totp.py` and
  `tests/test_passwords.py` exercise it with no HTTP involved at all.
* **The data layer enforces its own constraints.** Unique indexes on username
  and email mean that even if an application check were bypassed, the database
  refuses — verified in `tests/test_models_and_admin.py`.

---

## 2. Component diagram

```
                           ┌─────────────────┐
                           │   Web browser   │
                           └────────┬────────┘
                                    │ HTTPS (production)
                           ┌────────▼────────┐
                           │  Gunicorn/WSGI  │
                           └────────┬────────┘
                                    │
             ┌──────────────────────▼──────────────────────┐
             │           Flask application factory          │
             │  before_request → idle timeout + load user   │
             │  after_request  → security headers           │
             │  error handlers → 400/403/404/429/500/CSRF   │
             └──┬──────────┬──────────┬──────────┬──────────┘
                │          │          │          │
        ┌───────▼──┐  ┌────▼─────┐ ┌──▼──────┐ ┌─▼────────┐
        │  auth    │  │   mfa    │ │  main   │ │  admin   │
        │ blueprint│  │ blueprint│ │blueprint│ │ blueprint│
        └───────┬──┘  └────┬─────┘ └──┬──────┘ └─┬────────┘
                │          │          │          │
                └──────────┴────┬─────┴──────────┘
                                │
        ┌───────────────────────▼────────────────────────────┐
        │                 SECURITY LAYER                      │
        │                                                     │
        │  ┌───────────┐ ┌──────────┐ ┌──────────┐           │
        │  │passwords  │ │  totp    │ │  crypto  │           │
        │  │ Argon2id  │ │ PyOTP    │ │ Fernet   │           │
        │  └───────────┘ └──────────┘ └──────────┘           │
        │  ┌───────────┐ ┌──────────┐ ┌──────────┐           │
        │  │ session   │ │  access  │ │  audit   │           │
        │  │ 3 states  │ │ RBAC     │ │ scrubbed │           │
        │  └───────────┘ └──────────┘ └──────────┘           │
        └───────────────────────┬────────────────────────────┘
                                │ SQLAlchemy
                    ┌───────────▼───────────┐
                    │        MySQL          │
                    └───────────────────────┘
                                ▲
                    ┌───────────┴───────────┐
                    │  Environment (.env)   │
                    │  SECRET_KEY           │
                    │  MFA_ENCRYPTION_KEY   │  ← never in the database
                    └───────────────────────┘
```

---

## 3. Context diagram (Level 0 / DFD context)

```
                    ┌────────────────────────┐
                    │     Standard user      │
                    └───┬────────────────▲───┘
    registration,       │                │   pages, QR code,
    credentials,        │                │   recovery codes,
    TOTP codes          │                │   status messages
                        ▼                │
        ┌───────────────────────────────────────────────┐
        │                                                │
        │         MULTI-FACTOR AUTHENTICATION            │
        │                   SYSTEM                       │
        │                                                │
        └───────┬───────────────▲───────────┬────────────┘
                │               │           │
  admin actions │               │ reports,  │ encrypted secrets,
  (activate,    │               │ audit     │ hashes, audit rows
  deactivate,   ▼               │ records   ▼
  unlock)  ┌─────────────┐      │     ┌──────────────┐
           │Administrator│──────┘     │ MySQL        │
           └─────────────┘            │ database     │
                                      └──────────────┘
                ▲                             ▲
                │ shared TOTP secret          │ key (never stored here)
                │ at enrollment only          │
        ┌───────┴────────┐            ┌───────┴────────┐
        │ Authenticator  │            │  Environment / │
        │ app on phone   │            │ secret storage │
        └────────────────┘            └────────────────┘
```

**External entities**

| Entity | Provides | Receives |
|--------|----------|----------|
| Standard user | Username, email, password, TOTP codes, recovery codes | Web pages, QR code, recovery codes, status messages |
| Administrator | Management actions, audit queries | User lists, audit records, statistics |
| Authenticator app | Generated six-digit codes | The TOTP secret, once, at enrollment |
| MySQL database | Stored records | Hashes, encrypted secrets, audit events |
| Environment | Encryption and signing keys | — |

---

## 4. Level 0 data flow diagram

```
  User                                                          Data stores
  ────                                                          ───────────

  registration data
      │
      ▼
  ┌─────────────────────┐   hashed password, role    ┌──────────────────┐
  │ 1.0  Register user  │───────────────────────────▶│ D1 users         │
  └─────────────────────┘                            │    roles         │
      │ confirmation                                 └──────────────────┘
      ▼
  username + password
      │
      ▼
  ┌─────────────────────┐   read hash, lockout state ┌──────────────────┐
  │ 2.0  Verify         │◀──────────────────────────▶│ D1 users         │
  │      password       │   update failure count     └──────────────────┘
  └──────┬──────────────┘
         │ credentials valid
         │
    ┌────┴─────┐  MFA enabled?
    │          │
   no          yes
    │           │
    │           ▼
    │   ┌─────────────────────┐  create pending   ┌──────────────────────┐
    │   │ 3.0  Create pending │──────────────────▶│ D5 pending_          │
    │   │      authentication │                   │    authentications   │
    │   └──────┬──────────────┘                   └──────────────────────┘
    │          │ prompt for code
    │          ▼
    │      TOTP code from user
    │          │
    │          ▼
    │   ┌─────────────────────┐  read encrypted   ┌──────────────────────┐
    │   │ 4.0  Verify second  │◀─────secret───────│ D2 mfa_credentials   │
    │   │      factor         │  write counter    └──────────────────────┘
    │   └──────┬──────────────┘
    │          │ code accepted
    └──────────┤
               ▼
       ┌─────────────────────┐  create session    ┌──────────────────────┐
       │ 5.0  Issue session  │───────────────────▶│ D6 server_sessions   │
       └──────┬──────────────┘                    └──────────────────────┘
              │ authenticated
              ▼
       ┌─────────────────────┐  authorisation     ┌──────────────────────┐
       │ 6.0  Serve          │◀───check role──────│ D1 users / roles     │
       │      protected page │                    └──────────────────────┘
              │
              ▼
       pages returned to user

  Every process above also writes to:                ┌──────────────────────┐
                                     ───────────────▶│ D7 audit_events      │
                                                     └──────────────────────┘
```

**Data stores**

| Ref | Store | Holds |
|-----|-------|-------|
| D1 | `users`, `roles` | Accounts, Argon2id hashes, role assignment, lockout state |
| D2 | `mfa_credentials` | Encrypted TOTP secret, confirmation, last accepted counter |
| D3 | `recovery_codes` | Argon2id hashes of backup codes, used markers |
| D4 | `password_reset_tokens` | SHA-256 token digests, expiry, used markers |
| D5 | `pending_authentications` | Half-authenticated state, expiry, attempt counter |
| D6 | `server_sessions` | Session payloads, keyed by opaque id |
| D7 | `audit_events` | Security events; never any secret |

---

## 5. Level 1 DFD — Process 4.0, second-factor verification

This is the security-critical process, so it is decomposed.

```
      submitted code + session's pending token
                      │
                      ▼
        ┌──────────────────────────────┐
        │ 4.1  Load pending record      │◀──── D5 pending_authentications
        │      by opaque token          │
        └──────────┬───────────────────┘
                   │
         expired / consumed / absent? ──yes──▶ redirect to login, audit
                   │ no
                   ▼
        ┌──────────────────────────────┐
        │ 4.2  Decrypt TOTP secret      │◀──── D2 mfa_credentials
        │      (Fernet, key from env)   │◀──── environment key
        └──────────┬───────────────────┘
                   │
         decryption failed? ──yes──▶ deny, audit, offer recovery code
                   │ no
                   ▼
        ┌──────────────────────────────┐
        │ 4.3  Compute candidate codes  │
        │      for steps n-1, n, n+1    │
        └──────────┬───────────────────┘
                   │
         no match? ──yes──▶ 4.6 count attempt, audit "invalid", generic error
                   │ match at counter c
                   ▼
        ┌──────────────────────────────┐
        │ 4.4  Replay check:            │
        │      is c > last_used_counter?│◀──── D2 mfa_credentials
        └──────────┬───────────────────┘
                   │
         c ≤ last? ──yes──▶ 4.6 count attempt, audit "replay", SAME generic error
                   │ no
                   ▼
        ┌──────────────────────────────┐
        │ 4.5  Accept:                  │
        │      store c as last_used     │────▶ D2 mfa_credentials
        │      consume pending record   │────▶ D5 pending_authentications
        │      audit success            │────▶ D7 audit_events
        └──────────┬───────────────────┘
                   │
                   ▼
            to 5.0 Issue session

        ┌──────────────────────────────┐
        │ 4.6  Count failed attempt     │────▶ D5 (attempts += 1)
        │      cap reached? destroy     │────▶ D7 audit_events
        │      pending state            │
        └──────────────────────────────┘
```

Two details worth noting for the report:

1. **4.4 happens after 4.3, not instead of it.** A replayed code is a *valid*
   code, so it must first match before the replay check can reject it. The
   audit log distinguishes `mfa_verify_failed` from
   `mfa_verify_replay_rejected`, but **the user sees the same message either
   way** — otherwise the error message itself would tell an attacker that the
   code they captured was genuine.

2. **4.6 destroys the pending state at the attempt cap**, so an attacker cannot
   grind codes against one half-authenticated session; they must start again
   from the password step, where rate limiting and lockout apply.

---

## 6. Level 1 DFD — Process 1.0, registration

```
     registration form
            │
            ▼
   ┌─────────────────────┐
   │ 1.1 Validate form    │  CSRF token, field formats, confirmation match
   └────────┬────────────┘
            │ valid
            ▼
   ┌─────────────────────┐
   │ 1.2 Check password   │  length, composition, predictability,
   │     policy           │  must not contain username or email local part
   └────────┬────────────┘
            │ acceptable
            ▼
   ┌─────────────────────┐
   │ 1.3 Check uniqueness │◀──── D1 users (case-insensitive)
   └────────┬────────────┘
            │ unique
            ▼
   ┌─────────────────────┐
   │ 1.4 Hash password    │  Argon2id, t=3, m=64 MiB, p=2, fresh salt
   └────────┬────────────┘
            │
            ▼
   ┌─────────────────────┐
   │ 1.5 Create account   │────▶ D1 users  (role = 'user', mfa_enabled = false)
   │     with 'user' role │────▶ D7 audit_events
   └────────┬────────────┘
            │  unique constraint violation? ──▶ roll back, generic message
            ▼
      confirmation to user
```

---

## 7. Authentication sequence diagram

The full two-step login, as implemented.

```
 Browser            Flask app          Security layer        MySQL      Phone
    │                   │                     │                │          │
    │ GET /auth/login   │                     │                │          │
    ├──────────────────▶│                     │                │          │
    │  form + CSRF tok  │                     │                │          │
    │◀──────────────────┤                     │                │          │
    │                   │                     │                │          │
    │ POST username+pw  │                     │                │          │
    ├──────────────────▶│                     │                │          │
    │                   │ find user           │                │          │
    │                   ├────────────────────────────────────▶│          │
    │                   │◀────────────────────────────────────┤          │
    │                   │ locked? active?     │                │          │
    │                   ├────────────────────▶│                │          │
    │                   │ verify Argon2id     │                │          │
    │                   ├────────────────────▶│ (~120 ms)      │          │
    │                   │◀────────────────────┤                │          │
    │                   │                     │                │          │
    │                   │ MFA enabled → create pending record  │          │
    │                   ├────────────────────────────────────▶│          │
    │                   │ session = {pending_token} only       │          │
    │                   │ audit: mfa_step_required             │          │
    │ 302 /mfa/verify   │                     │                │          │
    │◀──────────────────┤                     │                │          │
    │                   │                     │                │          │
    │ ──── user opens authenticator app ──────────────────────────────────▶│
    │ ◀─── six-digit code for current 30 s step ──────────────────────────┤
    │                   │                     │                │          │
    │ POST code         │                     │                │          │
    ├──────────────────▶│                     │                │          │
    │                   │ load pending (valid? not expired?)   │          │
    │                   ├────────────────────────────────────▶│          │
    │                   │ decrypt secret (key from environment)│          │
    │                   ├────────────────────▶│                │          │
    │                   │ verify code in window n-1, n, n+1    │          │
    │                   ├────────────────────▶│                │          │
    │                   │ replay check: counter > last_used?   │          │
    │                   ├────────────────────────────────────▶│          │
    │                   │ store counter, consume pending       │          │
    │                   ├────────────────────────────────────▶│          │
    │                   │ ROTATE session id, create session row│          │
    │                   ├────────────────────────────────────▶│          │
    │                   │ audit: mfa_verify_success            │          │
    │ 302 /dashboard    │                     │                │          │
    │◀──────────────────┤                     │                │          │
    │                   │                     │                │          │
    │ GET /dashboard    │                     │                │          │
    ├──────────────────▶│ @login_required → full session? yes  │          │
    │ 200 dashboard     │                     │                │          │
    │◀──────────────────┤                     │                │          │
```

---

## 8. The three authentication states

The state machine is deliberately small, because a complicated one is where
bypasses hide.

```
                      ┌───────────────┐
                      │  ANONYMOUS    │
                      │ no session    │
                      │ keys set      │
                      └───┬───────┬───┘
                          │       │
         password correct │       │ password correct
         AND mfa_enabled  │       │ AND NOT mfa_enabled
                          ▼       │
              ┌──────────────────┐│
              │     PENDING      ││
              │ session holds    ││
              │ only an opaque   ││
              │ pending_token    ││
              │                  ││
              │ NO protected     ││
              │ page reachable   ││
              └───┬──────────┬───┘│
                  │          │    │
    valid TOTP or │          │ expired / attempts
    recovery code │          │ exhausted / logout
                  ▼          ▼    │
         ┌────────────────┐  back to ANONYMOUS
         │ AUTHENTICATED  │◀───────┘
         │ session holds  │
         │ auth_user_id   │
         │ + rotated sid  │
         └───┬────────────┘
             │ logout, idle timeout, account deactivated
             ▼
         ANONYMOUS (session row deleted)
```

**The guarantee:** `session["auth_user_id"]` is written in exactly one function,
`complete_login()` in `app/security/session.py`, which is called from exactly
two places — a password-only login for an account without MFA, and a successful
second-factor verification (TOTP or recovery code). There is no third path.

---

## 9. Request lifecycle

Every request passes through the same pipeline, so a control cannot be skipped
by adding a new route and forgetting something.

```
  1. Gunicorn receives the request
  2. ProxyFix (if TRUST_PROXY_HEADERS) resolves the real client IP
  3. before_request:
       a. touch_session()  → idle timeout; expired sessions are revoked here
       b. load_current_user() → g.user, g.pending_user
  4. Route decorators (in order):
       @anonymous_required / @login_required / @admin_required / @pending_required
       @limiter.limit(...)  → 429 if the per-IP budget is spent
  5. CSRF validation for state-changing methods (Flask-WTF)
  6. Form validation (WTForms, server-side)
  7. View body: calls into the security layer, reads/writes via the ORM
  8. Audit event written
  9. after_request: security headers added
       CSP · X-Frame-Options · X-Content-Type-Options · Referrer-Policy
       Permissions-Policy · Cache-Control: no-store · HSTS in production
 10. Session saved: server_sessions row written, opaque id set in the cookie
```

---

## 10. Design decisions and their trade-offs

| Decision | Alternative considered | Why this one | Cost accepted |
|----------|----------------------|--------------|---------------|
| **Server-side pending state** | A flag in the session cookie | A cookie flag is client-held; the authoritative record must be server-side, with an expiry and an attempt cap | One extra table and a row per login attempt |
| **Database-backed sessions** | Flask's default signed cookie | The specification requires server-side sessions; it also enables real revocation on logout and on account deactivation, and keeps one-time recovery codes out of the browser's cookie jar | A database read per request; rows to sweep |
| **Replay prevention by stored counter** | Accept any code in the window | Without it the same code works repeatedly for ~90 s | A user cannot log in twice within one 30-second step; documented in the user manual |
| **±1 step skew window** | 0 steps (strict) or ±2 (lenient) | ±1 tolerates ordinary device clock drift; wider windows lengthen the usefulness of a captured code | Slight increase in replay window, mitigated by the counter check |
| **Argon2id at 64 MiB** | bcrypt, PBKDF2 | Memory hardness resists GPU cracking far better | ~120 ms per login; capped by rate limiting |
| **TOTP secrets encrypted at rest** | Store base32 plaintext | A database dump alone must not yield working seeds | Key management becomes a real operational duty |
| **Recovery codes hashed** | Store plaintext so they can be re-displayed | Hashes mean a dump yields nothing; display-once is the correct trade | Lost codes cannot be recovered, only regenerated |
| **Generic login errors** | Say "no such user" | Prevents account enumeration | Slightly less helpful to a genuinely confused user |
| **Reset does not disable MFA** | Auto-disable for convenience | Auto-disabling turns email access into an MFA bypass | A user who has lost both factors needs an administrator |
| **No self-service MFA reset** | Allow reset via email | Same reason as above | Administrator workload, and a documented verification procedure |
| **Bootstrap served locally** | CDN | Lets the CSP forbid third-party script origins entirely; also works offline for the demonstration | ~310 KB in the repository |

---

## 11. Technology justification

| Choice | Why, specifically |
|--------|------------------|
| **Flask** over Django | Django ships its own auth system; using it would have meant demonstrating Django's security rather than building and understanding the controls. Flask provides routing and templating and leaves the authentication design to the project — which is the whole point of the project. |
| **Argon2id** over bcrypt | Winner of the Password Hashing Competition; memory-hard, so GPU and ASIC attacks lose most of their advantage. The `id` variant resists both side-channel and time-memory trade-off attacks. |
| **PyOTP** | Small, maintained, correct implementation of RFC 4226/6238. Cross-checked against it directly in `tests/test_totp.py` rather than trusted blindly. |
| **Fernet** over raw AES | Authenticated encryption with a sane, misuse-resistant interface: random IV per message, HMAC-SHA256 integrity. Hand-rolled AES-CBC without a MAC is a classic source of real vulnerabilities. |
| **SQLAlchemy ORM** | Parameterised queries by construction, so SQL injection is prevented structurally rather than by remembering to escape. Also gives migrations through Alembic. |
| **MySQL** | Required by the project specification; widely deployed and available on the target environment. Verified here on MariaDB 10.11.14, which speaks the same protocol and dialect. |
| **PyMySQL** over mysqlclient | Pure Python, so it installs without a C compiler or MySQL development headers — materially easier for a marker reproducing the build on Windows. |
