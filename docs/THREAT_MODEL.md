# Threat Model

**Project:** Multi-Factor Authentication (MFA) System for Securing Web Applications
**Student:** Yahye Ahmed Adan · ISBAT University, Kampala
**Phase 2 deliverable** · 23 October 2026

This document addresses objective 2: analysing the security risks of
password-only authentication and establishing which of them this system
addresses — and, just as importantly, which it does not.

---

## 1. Assets

What an attacker would want, ordered by what their loss would cost.

| # | Asset | Why it matters | Where it lives |
|---|-------|---------------|----------------|
| A1 | **User credentials** (passwords) | Direct account access; reused elsewhere | `users.password_hash` — Argon2id only |
| A2 | **TOTP secrets** | Lets an attacker generate valid codes forever | `mfa_credentials.secret_encrypted` — Fernet-encrypted |
| A3 | **Recovery codes** | Each one bypasses the second factor once | `recovery_codes.code_hash` — Argon2id only |
| A4 | **Session identifiers** | Direct impersonation of a signed-in user | `server_sessions.sid`; cookie holds only the id |
| A5 | **Pending-authentication tokens** | Could complete a half-finished login | `pending_authentications.token`, short-lived |
| A6 | **Password-reset tokens** | Account takeover via reset | `password_reset_tokens.token_hash` — SHA-256 only |
| A7 | **Protected resources** | The thing being protected | `/dashboard`, `/resources`, `/profile` |
| A8 | **Administrative functions** | Account control across all users | `/admin/*` |
| A9 | **Audit log integrity** | Without it, an intrusion cannot be reconstructed | `audit_events` |
| A10 | **Personal data** | Usernames, emails, IP addresses | `users`, `audit_events` |
| A11 | **Encryption key** | Decrypts every TOTP secret at once | Environment variable, never in the database |

---

## 2. Trust boundaries

```
                    ┌──────────────────────────────────────────┐
   UNTRUSTED        │              TRUSTED                      │
                    │                                           │
  ┌──────────┐      │   ┌─────────────┐      ┌──────────────┐   │
  │ Browser  │─────────▶│ Flask app   │─────▶│   MySQL      │   │
  │ (user or │  TB1 │   │ (app logic, │ TB2  │  (persisted  │   │
  │ attacker)│◀─────────│  security   │◀─────│   data)      │   │
  └──────────┘      │   │  layer)     │      └──────────────┘   │
                    │   └──────┬──────┘                         │
  ┌──────────┐      │          │ TB3                            │
  │ User's   │      │          ▼                                │
  │ phone    │      │   ┌─────────────┐                         │
  │ (TOTP)   │      │   │ Environment │  MFA_ENCRYPTION_KEY     │
  └──────────┘      │   │  / secrets  │  SECRET_KEY             │
                    │   └─────────────┘                         │
                    └──────────────────────────────────────────┘
```

| Boundary | Crosses | Rule enforced |
|----------|---------|---------------|
| **TB1** | Browser ↔ application | *Nothing from the client is trusted.* All validation, all authentication decisions and all authorisation checks happen server-side. The session cookie carries an opaque id only. |
| **TB2** | Application ↔ database | The database holds no usable plaintext secret. A full dump yields password hashes, encrypted TOTP seeds and recovery-code hashes — none directly usable. |
| **TB3** | Application ↔ environment | The encryption key lives outside the database, so compromising one does not compromise the other. |

The deliberate consequence of TB2 and TB3 together: **a stolen database backup
is not enough to impersonate a user.** The attacker would also need the
application host's environment.

---

## 3. Attacker profiles

| Profile | Capability | Motivation | Primary threats |
|---------|-----------|------------|-----------------|
| **Opportunistic remote attacker** | Credential lists from other breaches; automated tools | Any account, in bulk | Credential stuffing, password spraying, brute force |
| **Targeted attacker** | Knows the victim; can craft phishing; patient | One specific account | Phishing, social engineering of account recovery |
| **Network observer** | Can see traffic on a shared or hostile network | Interception | Session hijacking, credential capture in transit |
| **Malicious insider / curious administrator** | Legitimate elevated access | Snooping; covering tracks | Reading others' secrets, tampering with audit records |
| **Database thief** | Obtained a dump via SQL injection, a stolen backup or a misconfigured server | Offline cracking | Offline attacks on stored credentials |
| **Malicious authenticated user** | A valid low-privilege account | Privilege escalation | Broken access control, IDOR, mass assignment |

---

## 4. STRIDE analysis

### 4.1 Spoofing — pretending to be another user

| Threat | Risk without controls | Control implemented | Residual risk |
|--------|----------------------|--------------------|---------------|
| **Credential stuffing** using a password leaked elsewhere | **Critical** — works instantly at scale | TOTP second factor: the password alone is insufficient (`login` creates only a pending state). Per-IP rate limiting. Per-account lockout. | **Low** for MFA-enabled accounts; **unchanged** for accounts that have not enrolled, which is why the dashboard prompts persistently |
| **Brute-force password guessing** | High | Argon2id makes each guess cost ~120 ms server-side; 5 failures lock the account for 15 minutes; 10 attempts per minute per IP | Low |
| **Password spraying** across many accounts | High — stays under per-account thresholds | Per-IP rate limit catches the cross-account pattern; the admin dashboard surfaces failed-login hotspots by username and source address | Low–Medium: a distributed botnet spreads across IPs. Detection, not prevention, is the honest answer here |
| **Account enumeration**, to build a target list | Medium | Identical generic message for unknown user and wrong password. Response time equalised by verifying against a *real* Argon2 hash in the unknown-user branch (measured difference 5.9 %, within noise) | Low. Registration still reports a taken username, which is unavoidable if users are to pick one |
| **Session hijacking** by stealing a cookie | High | HttpOnly (no JavaScript access); SameSite=Lax; Secure in production; opaque server-side id; session deleted on logout; 15-minute idle timeout | Low over HTTPS; **High if deployed over plain HTTP** — hence the production requirement |
| **Session fixation** | Medium | Session id rotated at every privilege change: password step, MFA completion, password change | Low |
| **Replaying an observed TOTP code** | Medium — valid for up to ~90 s | Each accepted time step is recorded; a code at or below it is refused thereafter | Low |
| **Real-time phishing proxy** relaying a live code | **High** | **Not mitigated.** TOTP cannot defeat this | **Accepted and documented.** See §6 |

### 4.2 Tampering — unauthorised modification

| Threat | Control | Residual risk |
|--------|---------|---------------|
| **SQL injection** | All database access goes through SQLAlchemy with parameter binding; no string-built SQL anywhere in the codebase | Low |
| **Cross-site request forgery** | Flask-WTF CSRF token on every state-changing form; logout is POST-only | Low |
| **Modifying the session cookie** to claim another identity | The cookie holds a signed, opaque id; all state is server-side and looked up by that id | Low |
| **Forging a pending-authentication token** to skip the second factor | 256-bit random token; authoritative record in the database with expiry and attempt cap | Low |
| **Tampering with an encrypted TOTP secret** | Fernet is authenticated encryption; a modified ciphertext fails to decrypt rather than yielding garbage | Low |
| **Rewriting audit records** | The application only INSERTs and SELECTs; `DEPLOYMENT.md` §9 documents revoking UPDATE/DELETE on that table from the runtime account | Medium: with full host compromise, or without that grant applied, an attacker could alter the table. True append-only needs off-host log shipping |
| **Mass assignment** — posting extra fields such as `role_id` | Models are populated field by field from validated form data; never from the raw request | Low (covered by an automated test) |

### 4.3 Repudiation — denying an action

| Threat | Control | Residual risk |
|--------|---------|---------------|
| A user denies signing in | Every authentication decision is logged with timestamp, outcome, source IP and user agent | Low |
| An administrator denies deactivating an account | Administrative actions record the acting administrator's id and the target | Low |
| Failed logins against non-existent usernames vanish | Recorded under `username_attempted` with a null user id, so spray patterns remain visible | Low |

### 4.4 Information disclosure

| Threat | Control | Residual risk |
|--------|---------|---------------|
| **Database dump reveals passwords** | Argon2id with per-user salt, 64 MiB memory cost — offline cracking is slow and parallelises poorly | Low for strong passwords; **a weak password is still crackable**, which is why the policy rejects predictable ones |
| **Database dump reveals TOTP secrets** | Fernet-encrypted with a key held in the environment, outside the database | Low, provided the key is not stored alongside the backup |
| **Database dump reveals recovery codes** | Argon2id hashes only | Low |
| **Secrets leaking into logs** | `audit.scrub()` strips OTP-shaped, recovery-code-shaped and token-shaped values from every event before it is written; a structural test asserts the table has no column that could hold one | Low |
| **Stack traces revealing internals** | Custom error pages; `DEBUG` off in production configuration | Low |
| **XSS stealing session data** | Jinja2 autoescaping; CSP with `script-src 'self'` and no `unsafe-inline`; HttpOnly cookie | Low |
| **Open redirect used in phishing** | `next` parameter restricted to same-site relative paths | Low |
| **Secrets in version control** | `.env` is git-ignored; `.env.example` contains placeholders only; no default admin password exists | Low |

### 4.5 Denial of service

| Threat | Control | Residual risk |
|--------|---------|---------------|
| **Lockout abuse** — deliberately locking a victim out by failing their login | Lockout is time-limited (15 minutes) rather than permanent; an administrator can clear it | **Medium — accepted.** Any account lockout mechanism can be abused this way. The alternative, no lockout, is worse |
| **Argon2 CPU exhaustion** — forcing expensive hashing | Rate limiting caps hashing operations per source address | Medium |
| **Request flooding** | Out of scope at application level; needs a reverse proxy or WAF | Accepted, documented |

### 4.6 Elevation of privilege

| Threat | Control | Residual risk |
|--------|---------|---------------|
| **A standard user reaching admin functions** | `@admin_required` runs server-side on every admin route, for GET and POST alike; hiding the navigation link is treated as cosmetic only | Low |
| **Self-promotion to administrator at registration** | Role is assigned by the server; extra posted fields are ignored | Low |
| **Reaching protected pages with only a password** | `@login_required` rejects the pending state and redirects to verification | Low — the central property, covered by multiple tests |
| **Last administrator deactivated, locking everyone out** | Refused: an administrator cannot deactivate themselves, nor the last active administrator | Low |
| **An administrator impersonating a user** | Administrators cannot read TOTP secrets or recovery codes, and there is no "log in as user" function | Low |

---

## 5. Risk register

Likelihood × Impact, assessed for this system as built.

| ID | Risk | Likelihood | Impact | Inherent | Control | Residual |
|----|------|-----------|--------|----------|---------|----------|
| R-01 | Credential stuffing against an MFA-enabled account | High | Critical | **Critical** | TOTP second factor | **Low** |
| R-02 | Credential stuffing against an account without MFA | High | Critical | **Critical** | Lockout, rate limiting, persistent prompting to enrol | **High** — honest assessment: MFA only protects those who turn it on |
| R-03 | Real-time phishing proxy | Medium | Critical | **High** | None effective | **High — accepted, documented** |
| R-04 | Offline cracking after a database breach | Low | Critical | **High** | Argon2id, strong password policy | **Low–Medium** |
| R-05 | TOTP secrets extracted from a stolen backup | Low | Critical | **High** | Encryption with an external key | **Low** |
| R-06 | Session hijacking | Medium | High | **High** | HttpOnly/SameSite/Secure, server-side sessions, rotation, idle timeout | **Low** over HTTPS |
| R-07 | Brute-force guessing | High | High | **High** | Argon2 cost, lockout, rate limiting | **Low** |
| R-08 | CSRF | Medium | High | **High** | CSRF tokens everywhere | **Low** |
| R-09 | SQL injection | Medium | Critical | **Critical** | Parameterised ORM queries | **Low** |
| R-10 | Stored or reflected XSS | Medium | High | **High** | Autoescaping, strict CSP | **Low** |
| R-11 | Privilege escalation to administrator | Low | Critical | **High** | Server-side RBAC | **Low** |
| R-12 | Lost device locking a user out | **High** | Medium | **Medium** | Recovery codes, shown once, downloadable | **Low** |
| R-13 | Lost device *and* lost recovery codes | Medium | Medium | **Medium** | Documented administrator identity-verification procedure | **Medium — accepted** |
| R-14 | Encryption key lost | Low | High | **Medium** | Documented backup requirement | **Medium** |
| R-15 | Audit log tampering by a compromised application | Low | High | **Medium** | Append-only usage; documented privilege revocation | **Medium** |
| R-16 | Deliberate lockout of a victim | Medium | Low | **Low** | Time-limited lockout; admin can clear | **Low — accepted** |
| R-17 | Reset link intercepted in the user's email | Low | High | **Medium** | Short expiry, single use, **and reset does not disable MFA** | **Low** — the attacker still faces the second factor |

---

## 6. Threats this system does **not** address

Stating these plainly is part of the work. A report that claims complete
protection would be wrong.

### 6.1 Real-time phishing (adversary-in-the-middle)

An attacker hosts a convincing replica of the login page. The victim enters
their password and then their current TOTP code. The attacker's server relays
both to the genuine site within the ~90-second validity window and obtains a
session.

**Why TOTP cannot stop this:** the code is a shared secret derived from time.
It is not bound to the website the user is actually talking to, so a code typed
into the wrong site is still a valid code for the right one.

**What would stop it:** WebAuthn/passkeys. The browser cryptographically binds
the signature to the origin, so a signature produced for `evil-example.com` is
worthless at the real site. This is recorded as the primary future enhancement
in `LIMITATIONS.md`.

**Partial mitigations present:** the short replay window limits how long a
captured code is useful, and audit logging would show an unusual source address
after the fact.

### 6.2 Compromised endpoint

If malware controls the user's computer or phone, it can read the password as
it is typed, read codes from the screen, or hijack an established session. No
server-side authentication control can fix a compromised endpoint.

### 6.3 Compromised server

An attacker with code execution on the application host holds the encryption
key, the session store and the database together. Every protection in this
document assumes the server itself is not compromised.

### 6.4 Supply-chain compromise

A malicious update to one of the dependencies could undermine everything.
Mitigated only partially, by pinning exact versions in `requirements.txt` so
that an unexpected version change is visible.

### 6.5 Social engineering of account recovery

The weakest point in any MFA deployment is usually the help desk. An attacker
who convinces an administrator to reset a victim's MFA bypasses it entirely.
This system deliberately provides **no self-service MFA reset**, and
`ADMIN_GUIDE.md` sets out an identity-verification procedure — but a procedure
is only as strong as the person following it.

### 6.6 Denial of service at network level

Volumetric attacks require infrastructure-level defences outside this
application.

---

## 7. Security design principles applied

| Principle | How it shows up here |
|-----------|---------------------|
| **Defence in depth** | A password compromise meets TOTP; a database breach meets hashing and encryption; a session theft meets rotation and idle timeout |
| **Fail securely** | A secret that cannot be decrypted denies access rather than allowing it; an unparseable session timestamp revokes the session |
| **Least privilege** | Standard users cannot reach admin routes; the documented MySQL grant withholds UPDATE/DELETE on the audit table |
| **Complete mediation** | Authorisation is checked on every request, not cached from an earlier one |
| **Economy of mechanism** | Three clearly separated authentication states rather than a web of flags |
| **Open design** | Security rests on keys and secrets, not on the code being secret; the whole implementation is published for assessment |
| **Psychological acceptability** | Enrollment is proved before it is enforced; recovery codes are issued automatically; messages explain what to do next |
| **Separation of duties** | Administrators manage accounts but cannot read second-factor secrets |
| **Secure defaults** | MFA secrets encrypted by default; new accounts get the lowest-privilege role; production refuses to start without explicit secrets |
