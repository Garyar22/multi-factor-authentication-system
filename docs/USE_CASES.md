# Use Cases

**Project:** Multi-Factor Authentication (MFA) System for Securing Web Applications
**Student:** Yahye Ahmed Adan · ISBAT University, Kampala

---

## 1. Use-case diagram

```
                  MULTI-FACTOR AUTHENTICATION SYSTEM
   ┌──────────────────────────────────────────────────────────────┐
   │                                                               │
   │   ┌────────────────────┐        ┌────────────────────┐       │
   │   │ UC-01 Register     │        │ UC-08 Reset        │       │
   │   │       account      │        │       password     │       │
   │   └────────────────────┘        └────────────────────┘       │
   │                                                               │
   │   ┌────────────────────┐                                     │
   │   │ UC-02 Sign in      │◀─────────┐                          │
   │   │  (password step)   │          │ «include»                │
   │   └─────────┬──────────┘          │                          │
   │             │ «extend» if MFA on  │                          │
   │             ▼                     │                          │
   │   ┌────────────────────┐    ┌─────┴──────────────┐          │
   │   │ UC-03 Verify       │    │ UC-12 Record       │          │
   │   │  second factor     │───▶│       audit event  │          │
   │   └─────────┬──────────┘    └────────────────────┘          │
   │             │ «extend» device lost     ▲                     │
   │             ▼                          │ «include»           │
   │   ┌────────────────────┐               │ (from all)          │
   │   │ UC-04 Sign in with │───────────────┘                     │
   │   │  a recovery code   │                                     │
   │   └────────────────────┘                                     │
   │                                                               │
   │   ┌────────────────────┐        ┌────────────────────┐       │
   │   │ UC-05 Enable MFA   │        │ UC-06 Disable MFA  │       │
   │   │  (enrollment)      │        │ «include» reauth   │       │
   │   └────────────────────┘        └────────────────────┘       │
   │                                                               │
   │   ┌────────────────────┐        ┌────────────────────┐       │
   │   │ UC-07 Regenerate   │        │ UC-09 Access a     │       │
   │   │  recovery codes    │        │   protected page   │       │
   │   └────────────────────┘        └────────────────────┘       │
   │                                                               │
   │   ┌────────────────────┐        ┌────────────────────┐       │
   │   │ UC-10 Manage user  │        │ UC-11 Review the   │       │
   │   │   accounts         │        │   audit log        │       │
   │   └────────────────────┘        └────────────────────┘       │
   │                                                               │
   └───────────────────────────────────────────────────────────────┘
        ▲                    ▲                          ▲
        │                    │                          │
  ┌─────┴──────┐      ┌──────┴───────┐         ┌────────┴────────┐
  │  Visitor   │      │Standard user │         │  Administrator  │
  │(unauth'd)  │      │(authenticated)│        │ (inherits user) │
  └────────────┘      └──────────────┘         └─────────────────┘
                             ▲
                             │ shares the TOTP secret at enrollment
                      ┌──────┴────────┐
                      │ Authenticator │
                      │ app (external)│
                      └───────────────┘
```

**Actor permissions**

| Use case | Visitor | Standard user | Administrator |
|----------|:-------:|:-------------:|:-------------:|
| UC-01 Register | ✔ | — | — |
| UC-02 Sign in (password) | ✔ | — | — |
| UC-03 Verify second factor | half-auth only | — | half-auth only |
| UC-04 Recovery-code sign-in | half-auth only | — | half-auth only |
| UC-05 Enable MFA | — | ✔ | ✔ |
| UC-06 Disable MFA | — | ✔ | ✔ |
| UC-07 Regenerate recovery codes | — | ✔ | ✔ |
| UC-08 Reset password | ✔ | — | — |
| UC-09 Access protected page | ✘ | ✔ | ✔ |
| UC-10 Manage accounts | ✘ | ✘ | ✔ |
| UC-11 Review audit log | ✘ | own events only | ✔ all events |

---

## UC-01 — Register an account

| | |
|---|---|
| **Actor** | Visitor |
| **Goal** | Obtain an account |
| **Preconditions** | Not signed in |
| **Postconditions** | Account exists with role `user`, MFA disabled, password stored as an Argon2id hash |
| **Requirements** | FR-01 … FR-05 |

**Main flow**

1. Visitor opens `/auth/register`.
2. System displays the form with a CSRF token and client-side strength hints.
3. Visitor submits username, email, optional full name, password and confirmation, and ticks the acknowledgement.
4. System validates the CSRF token.
5. System validates field formats server-side.
6. System checks the password against the policy.
7. System checks that username and email are unused, case-insensitively.
8. System hashes the password with Argon2id.
9. System creates the account with the `user` role.
10. System records `register_success`.
11. System redirects to sign-in with a message inviting the user to enable two-step verification.

**Alternate flows**

| # | Condition | System response |
|---|-----------|-----------------|
| 3a | CSRF token missing or invalid | HTTP 400, security-check page; nothing created |
| 5a | Email syntactically invalid | Field error; form redisplayed with input preserved (password fields cleared) |
| 6a | Password fails the policy | Every failing rule listed; nothing created |
| 6b | Password contains the username or email local part | Specific message; nothing created |
| 7a | Username taken | "That username is already taken"; `register_failed` recorded |
| 7b | Email registered | "An account with that email already exists" |
| 9a | Two simultaneous registrations race | Database UNIQUE constraint rejects the second; transaction rolled back; generic message |
| 3b | Rate limit exceeded | HTTP 429 |

---

## UC-02 — Sign in (password step)

| | |
|---|---|
| **Actor** | Visitor |
| **Goal** | Complete the first authentication factor |
| **Postconditions** | *Either* a full session (MFA off) *or* a pending authentication record (MFA on) |
| **Requirements** | FR-08 … FR-13 |

**Main flow**

1. Visitor opens `/auth/login`.
2. Visitor submits identifier and password.
3. System validates the CSRF token and applies the rate limit.
4. System looks up the account by username **or** email, case-insensitively.
5. System checks the account is not locked.
6. System checks the account is active.
7. System verifies the password against the Argon2id hash.
8. System resets the failure counter.
9. **If MFA is enabled and confirmed**, the system creates a pending authentication record, rotates the session id, stores only the opaque token, records `mfa_step_required`, and redirects to UC-03.
10. **If MFA is not enabled**, the system creates a full session, records `login_success`, and redirects to the dashboard with a prompt to enable two-step verification.

**Alternate flows**

| # | Condition | System response |
|---|-----------|-----------------|
| 4a | No such account | Verifies against a **real** dummy Argon2id hash so the timing matches a genuine check; records `login_failed` with `username_attempted`; generic error, HTTP 401 |
| 5a | Account locked | `login_blocked_locked`; "temporarily locked" message, HTTP 403. **Checked before the password**, so a correct guess during lockout reveals nothing |
| 6a | Account deactivated | `login_blocked_inactive`; the **same generic** error as a wrong password, HTTP 403 |
| 7a | Wrong password | Failure counter incremented; `login_failed`; generic error, HTTP 401 |
| 7b | Failure counter reaches the threshold | Account locked for the configured period; `account_locked` recorded |
| 3a | Rate limit exceeded | HTTP 429; `login_rate_limited` recorded |
| 2a | `next` parameter points off-site | Ignored; user sent to the dashboard (open-redirect protection) |

---

## UC-03 — Verify the second factor

| | |
|---|---|
| **Actor** | Half-authenticated user |
| **Goal** | Complete authentication with a TOTP code |
| **Preconditions** | A valid pending authentication record exists |
| **Postconditions** | Full session issued; the code's time step is burned |
| **Requirements** | FR-12, FR-20, FR-21 |

**Main flow**

1. System displays the verification page, showing which account is signing in.
2. User reads the current six-digit code from their authenticator app and submits it.
3. System loads the pending record by the opaque token and confirms it is live.
4. System decrypts the stored TOTP secret using the key from the environment.
5. System computes the valid codes for steps *n−1*, *n* and *n+1*.
6. System finds a match at step *c*.
7. System checks that *c* is **strictly greater** than `last_used_counter`.
8. System stores *c*, consumes the pending record, rotates the session id and issues a full session.
9. System records `mfa_verify_success`.
10. System redirects to the dashboard.

**Alternate flows**

| # | Condition | System response |
|---|-----------|-----------------|
| 3a | Pending record expired, consumed or absent | Redirect to sign-in: "Your verification session expired" |
| 4a | Secret cannot be decrypted (wrong or lost key) | Access denied, `mfa_verify_failed` recorded, user directed to recovery codes. **Fails closed** |
| 6a | No match in the window | Attempt counted; `mfa_verify_failed`; generic error, HTTP 401 |
| 7a | Code already used (*c* ≤ last used) | Attempt counted; `mfa_verify_replay_rejected` recorded — but the user sees **the identical generic error**, so the message does not confirm that the captured code was genuine |
| 6b/7b | Attempt cap reached | Pending record destroyed; user must start again from the password step |
| 2a | Device lost | User follows the link to UC-04 |

---

## UC-04 — Sign in with a recovery code

| | |
|---|---|
| **Actor** | Half-authenticated user without their device |
| **Requirements** | FR-24 … FR-27 |

**Main flow**

1. User opens `/mfa/recovery` from the verification page.
2. User enters one of the codes saved at enrollment.
3. System normalises the input (case, spaces, optional dash).
4. System checks it against every **unused** code hash for that account.
5. On a match, the system marks that code used, consumes the pending record and issues a full session.
6. System records `mfa_recovery_code_used`, including how many codes remain.
7. System signs the user in and warns them to generate a fresh set.

**Alternate flows**

| # | Condition | System response |
|---|-----------|-----------------|
| 4a | Code unknown | Attempt counted; `mfa_recovery_code_failed`; HTTP 401 |
| 4b | Code already used | Same as 4a — a used code is indistinguishable from an invalid one |
| 4c | All codes spent | Same response; the user needs the administrator procedure in `ADMIN_GUIDE.md` |

---

## UC-05 — Enable two-step verification (enrollment)

| | |
|---|---|
| **Actor** | Authenticated user |
| **Preconditions** | Fully authenticated; MFA not already enabled |
| **Postconditions** | `mfa_enabled = true`, credential confirmed, ten recovery codes issued |
| **Requirements** | FR-15 … FR-19, FR-23, FR-24, FR-25 |

**Main flow**

1. User opens `/mfa/enroll`.
2. System generates a fresh 160-bit base32 secret.
3. System encrypts it and stores it as **unconfirmed**.
4. System renders a QR code as an inline data URI, plus the key for manual entry and the parameters (6 digits, 30 s).
5. System records `mfa_enroll_started`.
6. User scans the code with their authenticator app.
7. User enters the code the app now shows.
8. System verifies it against the stored secret.
9. System marks the credential confirmed, sets `mfa_enabled`, and stores the accepted counter.
10. System generates ten recovery codes, stores only their hashes, and holds the plaintext in the server-side session for one-time display.
11. System records `mfa_enroll_completed` and `mfa_recovery_codes_generated`.
12. System shows the codes once, with download, print and "I have saved these" options.

**Alternate flows**

| # | Condition | System response |
|---|-----------|-----------------|
| 7a | Code wrong | `mfa_enroll_failed`; HTTP 401; **MFA stays off** — this is what prevents a mis-scan from locking the user out |
| 1a | User abandons the page | Nothing is enabled; an unconfirmed credential is harmless and is replaced next time |
| 1b | Page reopened | A **new** secret is issued, so an abandoned enrollment leaves nothing usable |
| 12a | User navigates away without saving | Codes are gone for good; they must regenerate (UC-07). Stated plainly on the page |

---

## UC-06 — Disable two-step verification

| | |
|---|---|
| **Actor** | Authenticated user |
| **Requirements** | FR-22 |

**Main flow**

1. User opens `/mfa/disable`.
2. System warns that the account will rely on the password alone and that recovery codes will be deleted.
3. User supplies their **current password**, a **current TOTP code**, and ticks the confirmation.
4. System verifies both factors.
5. System deletes the credential and all recovery codes, and clears `mfa_enabled`.
6. System records `mfa_disabled`.

**Alternate flows**

| # | Condition | System response |
|---|-----------|-----------------|
| 4a | Password wrong | HTTP 401; MFA remains enabled |
| 4b | Code wrong or replayed | HTTP 401; MFA remains enabled |
| 3a | Confirmation not ticked | Form error; nothing changes |

**Why both factors.** If a session alone were enough, an attacker who stole a
session cookie could strip the second factor and then return at leisure with
only the password.

---

## UC-07 — Regenerate recovery codes

**Main flow:** user reauthenticates with their password → system generates a new
set of ten, **deleting the previous set** → records
`mfa_recovery_codes_generated` → displays the new codes once.

**Alternate flow:** wrong password → HTTP 401, old codes untouched.

---

## UC-08 — Reset a forgotten password

| | |
|---|---|
| **Actor** | Visitor |
| **Requirements** | FR-29, FR-30 |

**Main flow**

1. Visitor opens `/auth/forgot-password` and submits their email address.
2. System looks for an active account with that address.
3. System invalidates any earlier unused tokens for that account.
4. System generates a 256-bit token, stores **only its SHA-256 digest** with an expiry.
5. System records `password_reset_requested`.
6. System presents the reset link. *(In this demonstration there is no mail server, so the link is shown on screen; the page states this and `LIMITATIONS.md` records it.)*
7. Visitor opens the link and sets a new password meeting the policy.
8. System updates the hash, marks the token used and clears any lockout.
9. **System does not touch MFA settings.**
10. System records `password_reset_completed`.

**Alternate flows**

| # | Condition | System response |
|---|-----------|-----------------|
| 2a | No such address, or inactive | **The same message as success**, so the page cannot be used to discover registered addresses. Recorded as a failure internally |
| 7a | Token expired, already used or unknown | "Invalid or expired"; `password_reset_invalid_token` recorded |
| 7b | New password fails the policy | Errors listed; token remains usable |
| 9a | Account had MFA enabled | **Second factor is still required at the next sign-in.** Without this, anyone with access to the user's email would have a complete MFA bypass |

---

## UC-09 — Access a protected page

**Main flow:** user requests `/dashboard`, `/resources` or `/profile` → the
`@login_required` decorator confirms a full session → the page is served.

**Alternate flows**

| # | Condition | System response |
|---|-----------|-----------------|
| a | Anonymous | `access_denied` recorded; redirect to sign-in with the path preserved |
| b | **Half-authenticated** | Redirect to the verification page. **This is the project's central guarantee** |
| c | Session idle beyond the timeout | Session revoked server-side; redirect to sign-in |
| d | Account deactivated mid-session | Session revoked on the next request |
| e | Standard user requests an admin page | HTTP 403; `access_denied` recorded with the acting user |

---

## UC-10 — Manage user accounts

| | |
|---|---|
| **Actor** | Administrator |
| **Requirements** | FR-35, FR-36, FR-38 |

**Main flow:** administrator opens `/admin/users` → searches or pages through
accounts → selects activate, deactivate or unlock → system applies it, records
the action **with the acting administrator's id**, and reports the outcome.

**Alternate flows**

| # | Condition | System response |
|---|-----------|-----------------|
| a | Administrator tries to deactivate **their own** account | Refused |
| b | Target is the **last active administrator** | Refused, so the deployment cannot be locked out of its own admin functions |
| c | Deactivation succeeds | Every live session for that user is deleted; the message states how many |
| d | Unknown user id | HTTP 404 |
| e | Non-administrator posts the same request directly | HTTP 403; recorded |

**Explicitly not available to administrators:** reading a user's TOTP secret or
recovery codes, resetting a user's MFA, or signing in as a user.

---

## UC-11 — Review the audit log

**Main flow:** administrator opens `/admin/audit` → filters by event type,
outcome or category → reviews paged results → the act of viewing is itself
recorded as `admin_view_audit`.

A standard user sees only their **own** recent events, on their dashboard.

---

## UC-12 — Record an audit event *(included by every other use case)*

**Main flow:** a security-relevant action occurs → the system assembles event
type, category, outcome, user, attempted username, IP, user agent and detail →
**the detail is passed through the scrubber**, which removes anything shaped
like an OTP, a recovery code or a token → the row is inserted.

**Alternate flow:** the insert fails → the error is logged to the application
log and swallowed, so that a logging problem can never break the request it was
describing.
