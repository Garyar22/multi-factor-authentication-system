# Test Results

**Project:** Multi-Factor Authentication (MFA) System for Securing Web Applications
**Student:** Yahye Ahmed Adan · ISBAT University, Kampala
**Phase 8 deliverable** · Executed 23 October 2026

Every figure in this document was produced by running the tests and recording
what the tools printed. Nothing here is estimated, and the defects found along
the way are reported in §5 rather than quietly fixed and forgotten.

---

## 1. Summary

| Measure | Result |
|---------|--------|
| **Automated tests, SQLite** | **219 passed, 0 failed** in 18.87 s |
| **Automated tests, MySQL (MariaDB 10.11.14)** | **219 passed, 0 failed** in 65.15 s |
| **Statement coverage of `app/`** | **88 %** (1 533 statements, 187 uncovered) |
| **System test, Gunicorn + MySQL + real browser** | **54 checks, 54 passed** |
| **Screenshots captured from the running application** | **33** |
| **Defects found during testing** | **7** (1 design, 3 implementation, 3 test) — all resolved |
| **Acceptance criteria met** | **12 of 12** |

---

## 2. Execution environment

```
Operating system   Linux 6.18 (x86-64)
Python             3.13.17
Database           MariaDB 10.11.14 (MySQL protocol and dialect)
Application server Gunicorn 26.2.0, 2 workers
Browser            Chromium (Playwright), 1366×900 and 390×844
Test framework     pytest 9.1.1, pytest-cov 7.1.0
Dependencies       exactly as pinned in requirements.txt
Date of execution  23 October 2026
```

---

## 3. Automated test suite

### 3.1 SQLite in memory

```
$ pytest -q
============================= 219 passed in 18.87s =============================
```

### 3.2 MySQL — the same suite, the real target database

```
$ MFA_TEST_DATABASE_URL="mysql+pymysql://mfa_user:***@127.0.0.1:3306/mfa_test_db?charset=utf8mb4" pytest -q
======================== 219 passed in 65.15s (0:01:05) ========================
```

Running on both matters: SQLite is far more permissive than MySQL about types
and constraints, so a suite that only ever ran on SQLite could pass while the
real deployment failed. It did not — the behaviour is identical on both.

### 3.3 Breakdown by module

| Module | Tests | What it covers |
|--------|------:|----------------|
| `test_security_controls.py` | 65 | Access control, RBAC, sessions, CSRF, headers, injection, rate limiting, audit hygiene, error handling |
| `test_auth_flow.py` | 34 | Registration, login, lockout, open redirect, password reset |
| `test_mfa_flow.py` | 33 | Enrollment, two-step login, replay, recovery codes, disabling MFA |
| `test_models_and_admin.py` | 24 | Database constraints, admin interface, profile and password change |
| `test_passwords.py` | 24 | Argon2id hashing, password policy, the dummy-hash timing defence |
| `test_crypto_and_recovery.py` | 22 | Fernet encryption, token hashing, recovery-code lifecycle |
| `test_totp.py` | 17 | TOTP generation, clock-skew window, replay prevention |
| **Total** | **219** | |

### 3.4 Coverage

```
$ pytest -q --cov=app --cov-report=term-missing
TOTAL                             1533    187    88%
```

| Module | Coverage | Comment |
|--------|---------:|---------|
| `security/crypto.py` | **100 %** | Every encryption path, including tampering and wrong-key failure |
| `security/totp.py` | **100 %** | Every verification branch, including replay |
| `mfa/qr.py` | **100 %** | |
| `extensions.py` | **100 %** | |
| `security/recovery.py` | 98 % | |
| `forms.py` | 98 % | |
| `security/server_session.py` | 98 % | |
| `security/access.py` | 97 % | |
| `models.py` | 96 % | |
| `admin/routes.py` | 95 % | |
| `main/routes.py` | 94 % | |
| `security/passwords.py` | 94 % | |
| `auth/routes.py` | 93 % | |
| `security/audit.py` | 93 % | Uncovered lines are defensive `except` branches |
| `security/session.py` | 92 % | |
| `mfa/routes.py` | 84 % | Uncovered: the "secret fails to decrypt" path, which needs key loss to reach |
| `__init__.py` | 75 % | Uncovered: file-logging setup and production-only secret checks |
| `cli.py` | 35 % | **Lowest, and stated honestly.** The CLI is exercised manually during setup, not by the suite |

The two deliberate gaps are the CLI (used interactively, verified by actually
running it — see §7) and production-only code paths such as the refusal to
start without `SECRET_KEY`, which cannot execute under the testing
configuration.

---

## 4. System test — Gunicorn, MySQL, real browser

A separate end-to-end walkthrough ran against the application served by
Gunicorn on MySQL, **with CSRF protection enabled** (the pytest suite disables
it so forms can be posted directly). 54 assertions, all passed.

Selected results, verbatim:

```
[PASS] Password stored as Argon2id hash, not plaintext  -- $argon2id$v=19$m=65536,t=3,p=2$V...
[PASS] POST without a CSRF token is refused (400)
[PASS] TOTP secret is ENCRYPTED at rest (ciphertext != plaintext)  -- stored=gAAAAABq23nALw65...
[PASS] Stored ciphertext decrypts back to the displayed secret
[PASS] Credential is unconfirmed until a code is proven
[PASS] Enrollment rejects a wrong code (401)
[PASS] Ten recovery codes are issued and displayed once  -- count=10
[PASS] Recovery codes stored only as hashes
[PASS] Correct password now redirects to the MFA step, not the dashboard  -- /mfa/verify
[PASS] Half-authenticated user BLOCKED from /dashboard  -- status=302 -> /mfa/verify
[PASS] Half-authenticated user BLOCKED from /resources  -- status=302 -> /mfa/verify
[PASS] Half-authenticated user BLOCKED from /profile  -- status=302 -> /mfa/verify
[PASS] Half-authenticated user BLOCKED from /security  -- status=302 -> /mfa/verify
[PASS] Half-authenticated user BLOCKED from /mfa/settings  -- status=302 -> /mfa/verify
[PASS] Half-authenticated user blocked from /admin/  -- status=302 -> /mfa/verify
[PASS] REPLAY of an already-used OTP is rejected  -- status=401
[PASS] Replay attempt did not grant a session
[PASS] The SAME recovery code cannot be reused  -- status=401
[PASS] A different unused recovery code still works
[PASS] Regular user gets 403 on the admin dashboard  -- status=403
[PASS] Administrator CAN reach the admin dashboard
[PASS] No password / recovery code / TOTP secret appears in audit detail
[PASS] Audit log contains 'mfa_verify_replay_rejected'

======================================================================
LIVE E2E RESULT: 54 passed, 0 failed, 54 total
======================================================================
```

---

## 5. Defects found, and what was done about them

This section exists because finding nothing would not have been credible.
Seven defects surfaced during development and testing; all are resolved.

### D-01 — **Design: sessions were client-side, not server-side** · Critical

**Found by:** reviewing the implementation against requirement "Authentication
state: secure server-side sessions."

**Problem.** Flask's default session is a *signed client-side cookie*: the whole
session dictionary is serialised into the cookie. The signature stops the
client modifying it, but it does not keep the contents secret, and the server
holds no record — so "logging out" merely asks the browser to forget the
cookie. A copy captured beforehand would keep working until expiry. Worse, the
freshly generated recovery codes were being held in that session for one-time
display, which meant **ten plaintext recovery codes were being sent to the
browser's cookie jar**.

**Fix.** Implemented a database-backed session store
(`app/security/server_session.py`): the cookie now carries only an opaque signed
id, all state lives in `server_sessions`, `logout()` deletes the row, the id
rotates at every privilege change, and an administrator deactivating an account
can revoke every one of that user's sessions at once.

**Re-tested:** TC-71 … TC-78 — all pass. Session id rotation and genuine
revocation are now verified by tests that did not previously exist.

---

### D-02 — **The account-enumeration timing defence did not work** · High

**Found by:** measuring it (TC-116), not by reading the code.

**Problem.** When a username did not exist, the login route verified the
password against a hand-written placeholder Argon2 string, the intention being
to spend the same time as a genuine check. But that string was **malformed**,
so argon2-cffi rejected it in microseconds instead of doing ~120 ms of work.
The "defence" therefore created exactly the signal it was meant to remove:
unknown usernames answered far faster than known ones, giving an attacker a
reliable oracle for which accounts exist.

**Fix.** `dummy_hash()` now computes a **real** Argon2id hash of a random value
once per process and caches it on the application. The unknown-user branch
verifies against that, so the work done matches a genuine verification.

**Measured before and after** (15 samples each, rate limiting disabled so it did
not confound the measurement):

| | Existing username | Unknown username | Difference |
|---|---|---|---|
| **Before the fix** | ~130 ms | **~1 ms** | Trivially distinguishable |
| **After the fix** | 146.6 ms median | 137.9 ms median | **8.7 ms (5.9 %)** — within noise |

**Tests added:** `TestDummyHash` (5 tests), including one that demonstrates a
malformed hash *would* be far too cheap, so the bug cannot silently return.

---

### D-03 — **The password policy accepted obviously weak passwords** · High

**Found by:** TC-07.

**Problem.** The blocklist compared the password to a list of common passwords
by exact match. `Password123!` satisfies every composition rule — twelve
characters, upper, lower, digit, symbol — and is not an exact match for
`password`, so it was accepted. The following all passed:
`Password123!`, `Qwerty123456!`, `Welcome2024!`, `Admin1234567!`,
`Letmein2026!`. These are precisely the passwords attackers try first.

**Fix.** `is_predictable()` now undoes the mangling attackers already automate
before consulting the blocklist: lower-case the candidate, strip trailing
digits and punctuation (the "add a year and a bang" pattern), strip leading
decoration, undo leetspeak substitutions, and also reject anything that is
essentially a keyboard run. The order matters — stripping must happen *before*
leetspeak is undone, or the trailing digits become letters and there is nothing
left to strip. That ordering mistake was made and corrected during the fix.

**Verified both directions:** ten weak-but-compliant passwords now rejected;
eighteen legitimate passphrases still accepted.

---

### D-04 — **The recovery-code download button could never work** · Medium

**Found by:** TC-53.

**Problem.** The settings page *popped* the one-time codes out of the session in
order to display them. By the time the user clicked "Download as a text file",
the codes were gone, so the download always failed with "codes can only be
downloaded immediately after they are generated" — which was impossible to
satisfy.

**Fix.** The page now *reads* the codes without consuming them. They are cleared
when the user downloads them, or presses the new "I have saved these" button.
Because sessions are now server-side (D-01), the plaintext never reaches the
browser's cookie jar in the meantime.

---

### D-05 — **An inline event handler violated the application's own CSP** · Medium

**Found by:** reviewing the template against the Content-Security-Policy.

**Problem.** The "Print this page" button used an `onclick` attribute. The CSP
sets `script-src 'self'` with no `unsafe-inline`, so the browser would have
blocked it — a control correctly configured, and then undermined by the markup.

**Fix.** Replaced with a `data-print-page` attribute and a handler registered in
the external `app.js`.

---

### D-06 — **Test defect: configuration read at import time could not be overridden** · Medium

**Found by:** the rate-limiting tests failing in the full suite but passing in
isolation.

**Problem.** `RATELIMIT_ENABLED` and the limit strings were class attributes
evaluated when `config.py` was imported. A test that set the environment
variable afterwards had no effect, so rate limiting was never actually enabled
and the tests could not have been measuring what they claimed.

**Fix.** Converted the rate-limit settings to properties, so they are read when
the application is built rather than when the module is imported. This also
makes the behaviour correct for any caller that configures the environment
after import.

---

### D-07 — **Test defect: two tests asserted the wrong behaviour** · Low

**Found by:** investigating failures that turned out to be the tests' fault, not
the application's.

1. A test generated a TOTP code three time steps into the future and expected
   it to be accepted. Codes outside the ±1 window are *correctly* rejected. The
   test now advances a patched clock, as a real user waiting for the next code
   would.
2. A test posted the same correct credentials repeatedly and expected
   throttling. After the first success the user is signed in, and
   `@anonymous_required` redirects before the limiter is consulted. The test now
   uses a fresh client per attempt, which tests the intended property properly.

Recording these matters: a test asserting the wrong thing is itself a defect,
and silently adjusting tests until they pass would have been the wrong response.

---

### Two further corrections to test data (not product defects)

* Demonstration accounts used `@example.test`, which `email_validator`
  correctly refuses as a special-use domain. Changed to the reserved
  `example.com`.
* A test password was `LiveDemo#2026$Pass` for the user `livedemo` — rejected
  because it contains the username. **The policy was working**; the test data
  was wrong.

---

## 6. Performance measurements

Measured on the development machine, against Gunicorn over loopback, using the
procedure fixed in `TEST_PLAN.md` §6.

### 6.1 Page response times (30 requests per page)

| Page | Path | Mean | Median | p95 | Min | Max |
|------|------|-----:|-------:|----:|----:|----:|
| Landing page | `/` | 6.5 ms | 5.5 ms | 7.2 ms | 4.0 ms | 34.1 ms |
| Login page | `/auth/login` | 6.8 ms | 6.8 ms | 7.8 ms | 4.5 ms | 8.2 ms |
| Registration page | `/auth/register` | 6.4 ms | 5.8 ms | 8.4 ms | 4.7 ms | 13.5 ms |
| Health probe | `/healthz` | 2.1 ms | 1.9 ms | 2.7 ms | 1.5 ms | 4.8 ms |

**NFR-05 target: median under 500 ms — met with a wide margin.**

The single 34.1 ms maximum on the landing page is the first request, before
caches and connection pools are warm.

### 6.2 Password hashing cost

Argon2id at production parameters: `t=3`, `m=65536 KiB (64 MiB)`, `p=2`.

| Operation | Mean | Median |
|-----------|-----:|-------:|
| Hash | 120.6 ms | 118.9 ms |
| Verify | 120.5 ms | 119.3 ms |

**NFR-06 target: 50–500 ms — met.**

This cost is deliberate. It is barely perceptible to a user signing in once, but
it caps an offline attacker to roughly eight guesses per second per core on
comparable hardware, and the 64 MiB memory requirement is what makes GPU
parallelisation ineffective.

### 6.3 Account-enumeration timing (after D-02)

| | Mean | Median |
|---|-----:|-------:|
| Existing username, wrong password | 145.7 ms | 146.6 ms |
| Non-existent username | 156.9 ms | 137.9 ms |

Median difference **8.7 ms — 5.9 %** of the known-user median, against a target
of under 20 %. The remaining variation is ordinary scheduling noise, not a
systematic signal.

### 6.4 Observed throughput

The 219-test MySQL run performed several thousand database operations and
hundreds of full authentication flows in 65 seconds without error, connection
exhaustion or deadlock.

**Stated plainly:** this is not a load test. No claim is made about concurrent
users or sustained throughput, because no load-testing tool was available.

---

## 7. Manually executed tests

These were performed by hand because they cannot be meaningfully automated
here. Each was actually carried out.

| ID | Test | Result |
|----|------|--------|
| TC-117 | Full desktop walkthrough at 1366×900 | **Pass** — 30 screenshots |
| TC-118 | Mobile walkthrough at 390×844 | **Pass** — 3 screenshots; no horizontal scroll, all controls reachable |
| TC-119 | Keyboard navigation of each form | **Pass** — visible focus ring, logical tab order, submit reachable by keyboard |
| TC-120 | System test on MySQL under Gunicorn | **Pass** — 54/54 |
| — | `flask db upgrade` on an empty MySQL database | **Pass** — all 8 tables created |
| — | `flask seed-roles` | **Pass** — "Roles ready. 2 created." |
| — | `flask create-admin` | **Pass** — administrator created; password prompted, never echoed |
| — | `flask show-config` | **Pass** — database password masked in the output |
| — | `flask generate-keys` | **Pass** — valid `SECRET_KEY` and Fernet key emitted |
| — | Security headers on a live response | **Pass** — CSP, X-Frame-Options, nosniff, Referrer-Policy, Cache-Control present |
| — | Session cookie inspection on a live response | **Pass** — `HttpOnly; Path=/; SameSite=Lax`, value is an opaque id |

Live header output, verbatim:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Content-Security-Policy: default-src 'self'; img-src 'self' data:; style-src 'self';
    script-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none';
    base-uri 'self'; object-src 'none'
Cache-Control: no-store
Set-Cookie: mfa_session=Ik9hNXBaYlR4YTZNb0ZvTmxZTDBoT2o4MWw3SVNJWjhMSGZSaUdpNTczenci...; HttpOnly; Path=/; SameSite=Lax
```

---

## 8. Acceptance criteria — verdict

| # | Criterion | Evidence | Verdict |
|---|-----------|----------|---------|
| 1 | A user can register and sign in securely | 34 tests in `test_auth_flow.py`; screenshots 02–08 | **Met** |
| 2 | A user can enrol an authenticator and verify a code | `test_mfa_flow.py`; screenshots 10, 12, 15, 18 | **Met** |
| 3 | **MFA accounts cannot reach protected resources on a password alone** | TC-32…36; 6 live checks; screenshot 16 | **Met** |
| 4 | Invalid, expired and reused codes are rejected | TC-38…41; `test_totp.py` replay tests; live replay check | **Met** |
| 5 | Recovery codes work and cannot be reused | TC-45…53; live reuse check; screenshots 20–22 | **Met** |
| 6 | Protected routes enforce authentication and authorisation | TC-62…65; screenshot 19 | **Met** |
| 7 | Administrator functions restricted to authorised users | TC-63…70; screenshots 27–30 | **Met** |
| 8 | Security events logged without exposing secrets | TC-95…102 | **Met** |
| 9 | Database and session handling follow secure practice | TC-71…80, TC-103…109 | **Met** |
| 10 | Automated tests executed and results documented | This document | **Met** |
| 11 | Setup, deployment and user instructions available | `DEPLOYMENT.md`, `USER_MANUAL.md`, `ADMIN_GUIDE.md` | **Met** |
| 12 | Genuine diagrams, screenshots, code and evidence available | `docs/`, 33 screenshots | **Met** |

**12 of 12 met.**

---

## 9. Known issues not fixed

Recorded rather than hidden. Full discussion in `LIMITATIONS.md`.

| Issue | Severity | Why it remains |
|-------|----------|----------------|
| TOTP is not phishing-resistant | High | Inherent to TOTP. WebAuthn is the answer, and is out of scope |
| Password reset links are displayed rather than emailed | Medium | No SMTP server available; the UI says so explicitly |
| In-memory rate limiting is per-process | Medium | Fine for a single-worker demonstration; Redis documented for multi-worker |
| A deliberate lockout can deny service to a legitimate user | Low | Inherent to any lockout; time-limited and clearable by an administrator |
| Audit log is append-only by convention plus a documented grant | Medium | True append-only needs off-host log shipping |
| CLI coverage is 35 % | Low | Exercised manually; every command was actually run (§7) |
