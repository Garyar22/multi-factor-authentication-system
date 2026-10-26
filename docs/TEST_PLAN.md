# Test Plan

**Project:** Multi-Factor Authentication (MFA) System for Securing Web Applications
**Student:** Yahye Ahmed Adan · ISBAT University, Kampala
**Phase 7 deliverable** · 23 October 2026

This document states **what will be tested and how it will be measured**, and
was fixed before results were recorded. Executed results are in
[`TEST_RESULTS.md`](TEST_RESULTS.md).

---

## 1. Objectives

1. Verify every functional requirement FR-01 … FR-45 from `REQUIREMENTS.md`.
2. Verify the security controls listed in `THREAT_MODEL.md` actually behave as
   claimed, by attempting the attack rather than inspecting the code.
3. Verify the non-functional requirements NFR-01 … NFR-13 against a stated
   measurement procedure.
4. Confirm the twelve acceptance criteria in the project specification.
5. Produce evidence that can be cited directly in the academic report.

---

## 2. Scope

### In scope

| Level | What it covers |
|-------|---------------|
| **Unit** | Password hashing and policy; TOTP generation, window and replay logic; encryption; recovery-code handling — tested without HTTP |
| **Integration** | Complete HTTP journeys through the Flask test client: registration, two-step login, enrollment, recovery, reset, admin actions |
| **Security** | Deliberate attempts to bypass controls: SQL injection, XSS, CSRF omission, MFA bypass, OTP replay, privilege escalation, open redirect, session forgery, account enumeration |
| **Model / constraint** | Database-level guarantees: unique constraints, cascades, structural absence of secret columns |
| **System** | The whole application under Gunicorn against MySQL, driven by a real browser |
| **Usability** | Walkthrough of each journey at desktop and mobile widths |
| **Performance** | Response time and hashing cost, measured rather than estimated |

### Out of scope

* Load testing beyond a documented light workload — no load-testing
  infrastructure is available, so no throughput claim will be made.
* Independent penetration testing — no external auditor; all testing is
  self-conducted.
* Browser-compatibility matrix testing — one browser engine (Chromium) is used.
* Any testing of third-party systems. **All testing is confined to this
  application on the author's own machine.**

---

## 3. Test environment

| Item | Value |
|------|-------|
| Operating system | Linux (kernel 6.18) |
| Python | 3.13.17 |
| Database under test | MariaDB 10.11.14 (MySQL-compatible), plus SQLite in memory for the fast suite |
| Application server | Gunicorn 26.2.0, 2 workers, for system tests |
| Browser | Chromium (Playwright-driven) at 1366×900 and 390×844 |
| Test framework | pytest 9.1.1, pytest-cov 7.1.0 |
| Dependencies | Exactly as pinned in `requirements.txt` |

**Test data policy.** All accounts use the reserved `example.com` domain and
passwords generated for the test run. No real person's data is used anywhere.

---

## 4. Test strategy

### 4.1 Two database backends, one suite

The suite runs unchanged against SQLite in memory (fast feedback) and against
MySQL (the real target). Running both guards against passing only because of a
backend quirk — SQLite is far more permissive about types and constraints than
MySQL.

### 4.2 Attempt the attack, do not inspect the code

A test that reads the source and confirms a decorator is present proves
nothing about runtime behaviour. Every security test therefore performs the
attack and asserts it fails: it posts without a CSRF token, requests a
protected page while half-authenticated, submits a used OTP, posts an admin
action as a standard user.

### 4.3 Determinism around time

TOTP depends on the clock. Rather than sleeping for thirty seconds, tests pass
an explicit timestamp to the TOTP functions, or advance a patched clock through
the `advance_clock` fixture. The suite is therefore fast and repeatable.

### 4.4 Isolation

Each test gets a fresh application and a fresh schema, created and dropped
around it, so no test can depend on another's leftovers or ordering.

### 4.5 Honest recording

Results are written **after** execution. Failures are recorded with the defect
they exposed, the fix, and the re-run outcome. No result is written in advance
of running it.

---

## 5. Entry and exit criteria

**Entry:** all planned features implemented; migrations apply to a clean MySQL
database; the application starts without error; dependencies installed at the
pinned versions.

**Exit:**

1. Every planned test case has been executed and its real outcome recorded.
2. No failing test remains in the delivered suite.
3. Every defect found is recorded with its fix and a re-run result.
4. All twelve acceptance criteria are demonstrably met.
5. Performance measurements are recorded with their procedure.

---

## 6. Measurement procedures *(defined before measurement)*

| Metric | Procedure | Target |
|--------|-----------|--------|
| **Test pass rate** | `pytest` on both backends; record the counts the tool prints | 100 % of delivered tests |
| **Statement coverage** | `pytest --cov=app --cov-report=term-missing`; record the TOTAL line | ≥ 80 % of `app/` |
| **Page response time** | 30 sequential GETs per page against Gunicorn on loopback; report mean, median, p95, min, max in milliseconds | Median < 500 ms |
| **Password hashing cost** | 12 hash and 12 verify operations at production parameters; report mean and median | 50 ms – 500 ms |
| **Enumeration timing leak** | 15 login POSTs with a wrong password for an existing username, 15 for a non-existent one, rate limiting disabled so it does not confound the measurement; compare medians | Difference < 20 % of the known-user median |
| **Mobile usability** | Render at 390×844; check no horizontal scroll, controls reachable, text legible | Pass / fail per page |

**Stated in advance:** no claim about concurrent users or throughput will be
made, because no load-testing tool is available. Response times are measured on
one developer machine over loopback and are **not** a prediction of production
performance.

---

## 7. Planned test cases

### 7.1 Registration (FR-01 … FR-05)

| ID | Test | Expected |
|----|------|----------|
| TC-01 | Register with valid details | Account created, role `user`, MFA off |
| TC-02 | Inspect the stored password | Argon2id hash; plaintext absent |
| TC-03 | Register a duplicate username | Rejected; nothing created |
| TC-04 | Register a duplicate email in different case | Rejected |
| TC-05 | Register with a password below the minimum length | Rejected with a specific message |
| TC-06 | Register with a password missing a character class | Rejected |
| TC-07 | Register with a predictable password (`Password123!`) | Rejected |
| TC-08 | Register with a password containing the username | Rejected |
| TC-09 | Register with a mismatched confirmation | Rejected |
| TC-10 | Register with an invalid email | Rejected |
| TC-11 | Register with illegal username characters | Rejected |
| TC-12 | Confirm the event is audited | `register_success` present |

### 7.2 Authentication (FR-08 … FR-14)

| ID | Test | Expected |
|----|------|----------|
| TC-13 | Sign in with correct credentials, MFA off | Session issued |
| TC-14 | Sign in by email instead of username | Works |
| TC-15 | Sign in with a wrong password | HTTP 401, generic message |
| TC-16 | Compare the response for an unknown user and a wrong password | **Identical** message and status |
| TC-17 | Sign in to a deactivated account | Refused; no reason disclosed |
| TC-18 | Fail repeatedly up to the threshold | Account locked |
| TC-19 | Use the **correct** password while locked | Still refused |
| TC-20 | Succeed after a failure | Failure counter reset |
| TC-21 | Let a lockout expire | Sign-in works again |
| TC-22 | Request logout by GET | HTTP 405 |
| TC-23 | Log out, then request a protected page | Redirected; session row deleted |

### 7.3 MFA enrollment (FR-15 … FR-19, FR-23)

| ID | Test | Expected |
|----|------|----------|
| TC-24 | Open enrollment while unauthenticated | Redirected to sign-in |
| TC-25 | Open the enrollment page | QR code and base32 key rendered |
| TC-26 | Inspect the stored secret | Fernet ciphertext; plaintext absent; decrypts to what was shown |
| TC-27 | Inspect the credential before confirmation | `confirmed_at` NULL; `mfa_enabled` false |
| TC-28 | Submit a wrong code at enrollment | Rejected; **MFA stays off** |
| TC-29 | Submit a valid code | MFA enabled; ten recovery codes shown |
| TC-30 | Reopen the enrollment page | A **different** secret is issued |
| TC-31 | Check the audit trail | `mfa_enroll_started`, `mfa_enroll_completed`, `mfa_recovery_codes_generated` |

### 7.4 Two-step login and MFA enforcement (FR-12, FR-20, FR-21) — **critical**

| ID | Test | Expected |
|----|------|----------|
| TC-32 | Submit the correct password for an MFA account | Redirect to `/mfa/verify`, **not** the dashboard |
| TC-33 | Request `/dashboard` while half-authenticated | **Blocked**, redirected to verification |
| TC-34 | Repeat for `/resources`, `/profile`, `/security`, `/mfa/settings` | All blocked |
| TC-35 | Request `/admin/` while half-authenticated | Blocked |
| TC-36 | Confirm the pending record exists server-side | Row present, valid, with an expiry |
| TC-37 | Submit a valid code | Full session; dashboard reachable |
| TC-38 | Submit an invalid code | HTTP 401; still no session |
| TC-39 | Submit a code generated from a **different** secret | Rejected |
| TC-40 | **Replay a code that already succeeded** | **Rejected**, and no session granted |
| TC-41 | Submit a code from two steps ago | Rejected (outside the window) |
| TC-42 | Let the pending record expire, then submit a valid code | Sent back to sign-in |
| TC-43 | Exhaust the attempt cap | Pending state destroyed |
| TC-44 | Open `/mfa/verify` with no pending state | Redirected to sign-in |

### 7.5 Recovery codes (FR-24 … FR-28)

| ID | Test | Expected |
|----|------|----------|
| TC-45 | Count the codes issued | Exactly ten, unique, no ambiguous characters |
| TC-46 | Inspect storage | Argon2id hashes only; no plaintext |
| TC-47 | Sign in with a recovery code | Succeeds |
| TC-48 | **Reuse the same code** | **Refused** |
| TC-49 | Use a different unused code | Succeeds |
| TC-50 | Submit an unknown code | Refused |
| TC-51 | Submit a code in lower case without the dash | Accepted (normalisation) |
| TC-52 | Regenerate the set, then try an old code | Old codes dead; new ones work |
| TC-53 | Download the codes twice | Second attempt refused (one-time) |

### 7.6 Password reset (FR-29, FR-30)

| ID | Test | Expected |
|----|------|----------|
| TC-54 | Request a reset for a known address | Generic confirmation |
| TC-55 | Request a reset for an unknown address | **Identical** confirmation |
| TC-56 | Inspect the stored token | SHA-256 digest only |
| TC-57 | Complete a reset | New password works; old one fails |
| TC-58 | Reuse the reset link | Refused |
| TC-59 | Use an expired token | Refused |
| TC-60 | **Reset the password of an MFA-enabled account** | **MFA still enforced afterwards** |
| TC-61 | Reset while the account is locked | Lockout cleared |

### 7.7 Authorisation and RBAC (FR-31 … FR-38)

| ID | Test | Expected |
|----|------|----------|
| TC-62 | Request each protected page anonymously | Redirected; `access_denied` recorded |
| TC-63 | Request each admin page as a standard user | HTTP 403 |
| TC-64 | **POST** an admin action as a standard user | HTTP 403; nothing changes |
| TC-65 | Request admin pages as an administrator | HTTP 200 |
| TC-66 | Register while posting `role=admin` and other extra fields | Role is still `user` (mass-assignment check) |
| TC-67 | Administrator deactivates their own account | Refused |
| TC-68 | Deactivate the last active administrator | Refused |
| TC-69 | Deactivate a signed-in user | Their sessions are revoked immediately |
| TC-70 | Administrator clears a lockout | Lockout and counter cleared |

### 7.8 Session security (NFR-04)

| ID | Test | Expected |
|----|------|----------|
| TC-71 | Inspect the session cookie | Opaque id only; payload not in the cookie |
| TC-72 | Inspect cookie flags | HttpOnly, SameSite present |
| TC-73 | Compare session ids before and after sign-in | **Rotated** (fixation defence) |
| TC-74 | Log out | Stored session row deleted |
| TC-75 | Exceed the idle timeout | Session revoked; redirected |
| TC-76 | Present an expired session row | Not honoured |
| TC-77 | Present an invented cookie value | Rejected |
| TC-78 | Change the password | Session rotated |

### 7.9 Injection and web attacks

| ID | Test | Expected |
|----|------|----------|
| TC-79 | Six SQL-injection payloads in the login form | None authenticates; the table survives |
| TC-80 | SQL injection in the admin search box | Treated as a literal string |
| TC-81 | Register with `<script>` in the full name, then view it as an admin | Escaped, not executed |
| TC-82 | Submit `<script>` as a username on the login page | Escaped in the response |
| TC-83 | POST with no CSRF token | HTTP 400 |
| TC-84 | POST with a forged CSRF token | HTTP 400 |
| TC-85 | POST with a valid CSRF token | Succeeds |
| TC-86 | Supply an absolute external URL as `next` | Ignored |
| TC-87 | Supply a protocol-relative URL as `next` | Ignored |
| TC-88 | Supply a backslash-prefixed URL as `next` | Ignored |
| TC-89 | Supply a legitimate relative `next` | Honoured |

### 7.10 Rate limiting (FR-11)

| ID | Test | Expected |
|----|------|----------|
| TC-90 | Repeated failed sign-ins from one address | HTTP 429 before the budget is far exceeded |
| TC-91 | Repeated **successful** sign-ins | Also throttled (the limit counts all attempts) |
| TC-92 | Repeated registrations | Throttled |
| TC-93 | Confirm throttling is audited | `login_rate_limited` recorded |
| TC-94 | Repeated **GET** requests | **Not** throttled — browsing stays usable |

### 7.11 Audit logging (FR-39 … FR-45)

| ID | Test | Expected |
|----|------|----------|
| TC-95 | Scan every audit row for the password used | **Absent** |
| TC-96 | Scan for the submitted OTP value | **Absent** |
| TC-97 | Scan for the recovery code used | **Absent** |
| TC-98 | Scan for the TOTP secret | **Absent** |
| TC-99 | Unit-test the scrubber directly | OTP-, code- and token-shaped values removed |
| TC-100 | Fail a login for a non-existent username | Recorded with `username_attempted`, null user id |
| TC-101 | Inspect an event's fields | Timestamp, outcome and category all present |
| TC-102 | Inspect the audit table's columns | **No column exists** that could hold a secret |

### 7.12 Model and database constraints

| ID | Test | Expected |
|----|------|----------|
| TC-103 | Insert a duplicate username directly via the ORM | `IntegrityError` |
| TC-104 | Insert a duplicate email directly | `IntegrityError` |
| TC-105 | Insert a user with no role | `IntegrityError` |
| TC-106 | Check a new account's defaults | Active, MFA off, zero failures |
| TC-107 | Delete a user with MFA and recovery codes | Dependent rows cascade away |
| TC-108 | Exercise the lock / unlock helpers | Behave as specified |
| TC-109 | Check a lock timestamp in the past | Not treated as locked |

### 7.13 Error handling

| ID | Test | Expected |
|----|------|----------|
| TC-110 | Request an unknown URL | Friendly 404 |
| TC-111 | Trigger a 403 | Friendly 403 |
| TC-112 | Inspect any error page | **No traceback or framework internals** |
| TC-113 | Call the health endpoint | Minimal JSON, nothing sensitive |

### 7.14 Performance and usability *(manual / measured)*

| ID | Test | Procedure |
|----|------|-----------|
| TC-114 | Page response times | 30 GETs per page; report the distribution |
| TC-115 | Hashing cost | 12 hash + 12 verify at production parameters |
| TC-116 | Enumeration timing | 15 + 15 login POSTs, limits disabled; compare medians |
| TC-117 | Desktop walkthrough | Complete every journey at 1366×900; capture screenshots |
| TC-118 | Mobile walkthrough | Repeat key pages at 390×844 |
| TC-119 | Keyboard accessibility | Tab through each form; confirm visible focus and reachable controls |
| TC-120 | System test on MySQL under Gunicorn | Full journey end to end |

---

## 8. Defect management

| Severity | Meaning | Action |
|----------|---------|--------|
| **Critical** | A security control can be bypassed | Fix before anything else; re-run the whole suite |
| **High** | A functional requirement is unmet | Fix and re-test |
| **Medium** | Incorrect behaviour with a workaround | Fix if time allows; otherwise record in `LIMITATIONS.md` |
| **Low** | Cosmetic or minor usability | Record |

Every defect is recorded in `TEST_RESULTS.md` §5 with its cause, its fix and
the outcome of re-running the affected tests — **including defects found in the
tests themselves**, since a test that asserts the wrong thing is also a defect.

---

## 9. Acceptance criteria traceability

| # | Criterion | Covered by |
|---|-----------|-----------|
| 1 | A user can register and sign in securely | TC-01 … TC-14 |
| 2 | A user can enrol an authenticator and verify a code | TC-24 … TC-31, TC-37 |
| 3 | **MFA accounts cannot reach protected resources on a password alone** | **TC-32 … TC-36** |
| 4 | Invalid, expired and reused codes are rejected | TC-38 … TC-41 |
| 5 | Recovery codes work and cannot be reused | TC-45 … TC-53 |
| 6 | Protected routes enforce authentication and authorisation | TC-62 … TC-65 |
| 7 | Administrator functions are restricted | TC-63 … TC-70 |
| 8 | Security events logged without exposing secrets | TC-95 … TC-102 |
| 9 | Database operations and sessions follow secure practice | TC-71 … TC-80, TC-103 … TC-109 |
| 10 | Automated tests executed and results documented | `TEST_RESULTS.md` |
| 11 | Setup, deployment and user instructions available | `DEPLOYMENT.md`, `USER_MANUAL.md`, `ADMIN_GUIDE.md` |
| 12 | Genuine diagrams, screenshots, code and evidence available | `docs/`, `docs/screenshots/` |
