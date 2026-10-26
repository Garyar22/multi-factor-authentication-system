# Requirements Analysis and Feasibility

**Project:** Multi-Factor Authentication (MFA) System for Securing Web Applications
**Student:** Yahye Ahmed Adan · ISBAT University, Kampala
**Phase 1 deliverable** · 23 October 2026

---

## 1. Problem statement

Most web applications still authenticate users with a single secret: a password.
That single factor carries the entire weight of access control, and it fails in
several predictable ways at once.

**Passwords are reused.** A user who registers on a university portal, a social
network and a shopping site typically uses the same or a closely related
password on all three. When any one of those sites is breached, the password
becomes available to attackers for all of them. The attacker does not need to
break the university's security at all — they simply log in.

**Password databases leak.** Breaches are routine, and a leaked database of
unsalted or weakly hashed passwords can be cracked offline at enormous speed
with commodity GPUs. Once cracked, the credentials work immediately, and the
legitimate owner has no signal that anything has happened.

**Passwords are guessable.** Human-chosen passwords cluster tightly around a
small set of patterns: a dictionary word, a capital letter at the front, a year
and an exclamation mark at the end. An attacker who tries the few thousand most
common patterns against many accounts — password spraying — succeeds often
enough to be worthwhile, while staying under per-account lockout thresholds.

**Passwords are phishable.** A convincing fake login page harvests the password
directly. The user believes they have logged in; the attacker now has the
credential.

The common thread is that **knowledge of one secret is sufficient**. If that
secret escapes by any route, access follows.

Multi-factor authentication changes the economics. By requiring a second factor
of a different kind — something the user *has*, in the form of a device
generating time-based codes — a stolen password stops being sufficient on its
own. The attacker must also obtain a value that changes every thirty seconds
and never leaves the user's device.

This project designs, builds, tests and evaluates such a system, and documents
honestly both what it achieves and where it stops.

---

## 2. Review of existing authentication approaches

This section addresses objective 1: studying existing systems and identifying
their strengths, weaknesses and limitations.

### 2.1 Password-only authentication

| | |
|---|---|
| **How it works** | The user supplies a secret; the server compares it (ideally a hash of it) against a stored value. |
| **Strengths** | Universally understood; nothing to carry; trivial to implement; no hardware cost; recovery is simple. |
| **Weaknesses** | Single point of failure. Vulnerable to reuse, offline cracking after a breach, guessing, phishing, keylogging and shoulder-surfing. |
| **Where it still fits** | Low-value accounts where the cost of a compromise is negligible. |

The weakness is structural, not a matter of implementation quality. Even a
perfectly implemented password system fails when the password is known to
someone else.

### 2.2 SMS one-time passwords

| | |
|---|---|
| **How it works** | After the password, the server sends a numeric code by text message. |
| **Strengths** | Requires no app installation; familiar; works on any phone, including feature phones — relevant in contexts where smartphone penetration is uneven. |
| **Weaknesses** | **SIM-swap attacks**: an attacker who persuades or bribes a mobile operator to move the victim's number to their own SIM receives every code. **SS7 interception** allows message interception at the network level. Delivery is unreliable and depends on network coverage. Per-message cost. NIST SP 800-63B deprecated SMS as a restricted authenticator for these reasons. |
| **Verdict for this project** | Rejected as the primary factor. A SIM swap in the user's own country defeats it entirely, and the mobile operator becomes part of the trust boundary. |

### 2.3 Email one-time codes / magic links

| | |
|---|---|
| **How it works** | A code or sign-in link is emailed. |
| **Strengths** | No extra hardware; no per-message cost beyond mail infrastructure. |
| **Weaknesses** | Reduces to the security of the email account, which is itself usually protected by a password. If the attacker has the password through reuse, they may well have the email password too. It is a second *channel*, not genuinely a second *factor*. |
| **Verdict** | Rejected as a primary second factor; a variant is used only for password reset, where the limitation is acknowledged. |

### 2.4 Time-based one-time passwords (TOTP, RFC 6238)

| | |
|---|---|
| **How it works** | Server and authenticator app share a secret at enrollment. Both compute HMAC-SHA1 over the secret and the current 30-second time step, truncating to six digits. The server accepts a code it can independently derive. |
| **Strengths** | Genuinely "something you have". The secret never leaves the device after enrollment. Works offline — no network, no SMS, no cost per use. Open standard with many interoperable apps. Immune to SIM swap and SS7. |
| **Weaknesses** | **Not phishing-resistant** — a real-time proxy can relay a code inside its window. Enrollment transfers the secret, so that moment matters. A lost or wiped device locks the user out unless recovery codes exist. Requires the device clock to be roughly correct. |
| **Verdict** | **Selected as the primary second factor** for this project: it defeats the dominant realistic threats (reuse, leaked databases, guessing) with no running cost and no dependency on a mobile operator. |

### 2.5 Push-notification approval

| | |
|---|---|
| **Strengths** | Low friction; can carry context such as location. |
| **Weaknesses** | **MFA fatigue**: an attacker with the password sends repeated prompts until the user taps "approve" to stop the noise. Needs network connectivity and a vendor service. |
| **Verdict** | Out of scope. It adds a third-party dependency and a well-documented human failure mode. |

### 2.6 WebAuthn / passkeys (FIDO2)

| | |
|---|---|
| **How it works** | Public-key cryptography. The authenticator signs a challenge, and the signature is **bound to the website's origin** by the browser. |
| **Strengths** | **Phishing-resistant** — this is the decisive property. A fake site cannot obtain a usable signature, because the browser will not produce one for the wrong origin. No shared secret to steal from the server. |
| **Weaknesses** | Needs a compatible browser and authenticator. More complex to implement correctly. Account recovery across devices is genuinely difficult. |
| **Verdict** | **The correct long-term answer**, and recorded as the primary future enhancement in `LIMITATIONS.md`. Out of scope here because TOTP meets the project objectives within the available time, and implementing WebAuthn badly would be worse than implementing TOTP well. |

### 2.7 Comparison summary

| Method | Second factor? | Phishing-resistant | Offline | SIM-swap safe | Running cost | Chosen |
|--------|---------------|--------------------|---------|---------------|--------------|--------|
| Password only | No | No | — | — | None | Baseline |
| SMS OTP | Yes | No | No | **No** | Per message | No |
| Email code | Weak | No | No | n/a | Low | Reset only |
| **TOTP** | **Yes** | **No** | **Yes** | **Yes** | **None** | **Yes** |
| Push approval | Yes | No | No | Yes | Service | No |
| WebAuthn | Yes | **Yes** | Yes | Yes | Hardware | Future work |

---

## 3. Project objectives

### General objective

To design, develop, implement and evaluate a multi-factor authentication system
that strengthens the security of web applications by requiring users to verify
their identity using multiple authentication factors.

### Specific objectives

1. Study existing authentication systems and identify their strengths,
   weaknesses and security limitations. *(Section 2 above.)*
2. Analyse the security risks associated with password-only authentication,
   including phishing, credential theft, brute-force attacks and unauthorised
   access. *(`THREAT_MODEL.md`.)*
3. Design an MFA architecture integrating secure password authentication with
   time-based one-time passwords. *(`ARCHITECTURE.md`.)*
4. Develop and integrate a web-based MFA system using Python, JavaScript,
   HTML, CSS and MySQL. *(The `app/` package.)*
5. Implement and test authentication security controls, usability, reliability
   and system performance. *(`TEST_PLAN.md`, `TEST_RESULTS.md`.)*
6. Deploy the application in a controlled environment and evaluate its
   effectiveness against the defined requirements. *(`DEPLOYMENT.md`,
   `PROJECT_EVIDENCE.md`.)*

---

## 4. Stakeholders

| Stakeholder | Interest | What the system must give them |
|-------------|----------|-------------------------------|
| **End user** | Access their account without being locked out or slowed down unreasonably | A clear two-step sign-in, a workable enrollment process, and a way back in when the phone is lost |
| **Administrator** | Keep accounts safe; investigate suspicious activity | User management, a trustworthy audit trail, visibility of failed-login patterns |
| **System owner / institution** | Reduce the risk and cost of account compromise | Demonstrable controls, evidence that they work |
| **Attacker** *(adversarial stakeholder)* | Gain unauthorised access | Must be denied: see `THREAT_MODEL.md` |
| **Project supervisor / examiner** | Assess whether the work meets the objectives | Running code, honest test evidence, documentation that matches the system actually built |

---

## 5. Scope

### 5.1 In scope

* User registration with server-side validation and a password policy
* Argon2id password hashing
* TOTP enrollment with QR code and manual key entry
* Two-step login with a server-side pending state
* TOTP verification with a documented clock-skew window and replay prevention
* Single-use recovery codes
* Password reset with expiring, single-use tokens
* Role-based access control (administrator and standard user)
* Protected demonstration pages
* Administrative dashboard, user management and audit-log viewer
* Security audit logging that excludes authentication secrets
* Brute-force protection: per-account lockout and per-IP rate limiting
* CSRF protection, secure session management, security headers
* Automated tests and documented, executed results
* Deployment in a controlled local environment

### 5.2 Explicitly out of scope

Listing these matters as much as listing what is included, because it prevents
the report from claiming more than the system does.

| Out of scope | Why |
|--------------|-----|
| WebAuthn / passkeys | Time; and TOTP satisfies the stated objectives. Recorded as future work. |
| SMS or voice OTP | Deliberately rejected (SIM swap, SS7, cost) — see §2.2 |
| Push approval | MFA fatigue; third-party dependency |
| Biometrics | Needs device hardware and raises data-protection questions beyond this project |
| Single sign-on / OAuth / SAML federation | A different problem domain |
| A real mail server for reset emails | No SMTP infrastructure available; the reset link is shown on screen in demonstration mode, and this limitation is stated in the UI and in `LIMITATIONS.md` |
| Production hardening (WAF, IDS, HA, DR) | Infrastructure concerns outside an application-level project |
| Independent penetration test | No external auditor available; self-testing only, on the author's own machine |

---

## 6. Functional requirements

Each requirement has an identifier used throughout the test plan and results.

### 6.1 Registration and account management

| ID | Requirement | Priority |
|----|------------|----------|
| FR-01 | A visitor can register with a unique username, a valid email address and a password | Must |
| FR-02 | All submitted data is validated on the server, independently of the browser | Must |
| FR-03 | Passwords must meet a documented strength policy | Must |
| FR-04 | Passwords are hashed with Argon2id before storage; plaintext is never stored | Must |
| FR-05 | Duplicate usernames and email addresses are rejected, case-insensitively | Must |
| FR-06 | A user can update their profile name | Should |
| FR-07 | A user can change their password after supplying the current one | Must |

### 6.2 Authentication

| ID | Requirement | Priority |
|----|------------|----------|
| FR-08 | A user can sign in with username or email, plus password | Must |
| FR-09 | Failed sign-in gives a generic message that does not reveal whether the account exists | Must |
| FR-10 | Repeated failures lock the account for a configured period | Must |
| FR-11 | Sign-in attempts are rate-limited per source address | Must |
| FR-12 | Where MFA is enabled, a correct password alone does **not** create a session | Must |
| FR-13 | The half-authenticated state is held server-side, expires, and limits attempts | Must |
| FR-14 | A user can sign out, and this invalidates the session server-side | Must |

### 6.3 Multi-factor authentication

| ID | Requirement | Priority |
|----|------------|----------|
| FR-15 | An authenticated user can enable TOTP two-step verification | Must |
| FR-16 | A unique TOTP secret is generated per user | Must |
| FR-17 | A QR code compatible with standard authenticator apps is displayed, plus the key for manual entry | Must |
| FR-18 | MFA is only activated after the user proves possession by entering a valid code | Must |
| FR-19 | TOTP secrets are encrypted at rest with a key stored outside the database | Must |
| FR-20 | A valid code within the skew window is accepted; invalid and expired codes are rejected | Must |
| FR-21 | An accepted code cannot be used a second time | Must |
| FR-22 | MFA can be disabled only after reauthentication with password **and** a current code | Must |
| FR-23 | MFA enrollment, disabling and reconfiguration are recorded in the audit log | Must |

### 6.4 Recovery

| ID | Requirement | Priority |
|----|------------|----------|
| FR-24 | Ten single-use recovery codes are generated when MFA is enabled | Must |
| FR-25 | Recovery codes are displayed exactly once and can be downloaded or printed | Must |
| FR-26 | Only hashes of recovery codes are stored | Must |
| FR-27 | A recovery code is invalidated immediately upon successful use | Must |
| FR-28 | A user can regenerate recovery codes after reauthentication, invalidating the old set | Should |
| FR-29 | Password reset uses an expiring, single-use token | Must |
| FR-30 | A password reset does **not** disable MFA | Must |

### 6.5 Authorisation and protected resources

| ID | Requirement | Priority |
|----|------------|----------|
| FR-31 | Unauthenticated users cannot access protected pages | Must |
| FR-32 | Half-authenticated users cannot access protected pages | Must |
| FR-33 | At least two roles exist: administrator and standard user | Must |
| FR-34 | Authorisation is enforced server-side on every protected operation | Must |
| FR-35 | Administrators can view users and account status | Must |
| FR-36 | Administrators can activate and deactivate accounts, and clear lockouts | Must |
| FR-37 | Administrators can view audit records and authentication statistics | Must |
| FR-38 | Administrators cannot read any user's TOTP secret or recovery codes | Must |

### 6.6 Audit logging

| ID | Requirement | Priority |
|----|------------|----------|
| FR-39 | Successful and failed sign-ins are recorded, including for unknown usernames | Must |
| FR-40 | MFA verification successes, failures and replay rejections are recorded | Must |
| FR-41 | Enrollment, removal, recovery and reset events are recorded | Must |
| FR-42 | Lockouts and rate-limiting events are recorded | Must |
| FR-43 | Administrative actions are recorded with the acting administrator's identity | Must |
| FR-44 | Logs contain timestamps, event categories and outcomes | Must |
| FR-45 | Logs **never** contain passwords, submitted OTP values, recovery codes, reset tokens or session identifiers | Must |

---

## 7. Non-functional requirements

| ID | Category | Requirement | How it is measured |
|----|----------|-------------|--------------------|
| NFR-01 | Security | Passwords hashed with a memory-hard algorithm at documented cost | Inspect stored hash; `TEST_RESULTS.md` §6 |
| NFR-02 | Security | No authentication secret appears in any log | Automated test scans every audit row |
| NFR-03 | Security | All state-changing requests carry CSRF protection | Automated test posts without a token |
| NFR-04 | Security | Session cookies are HttpOnly and SameSite; Secure in production | Inspect response headers |
| NFR-05 | Performance | Interactive pages respond in under 500 ms on the development machine | Measured over 30 requests per page |
| NFR-06 | Performance | Password hashing takes between 50 ms and 500 ms | Measured over 12 operations |
| NFR-07 | Usability | The second-factor step is reachable and completable without instruction | Walkthrough; screenshots |
| NFR-08 | Usability | Interface is responsive from 360 px upward | Rendered at 390×844 and 1366×900 |
| NFR-09 | Accessibility | Form controls are labelled; focus is visible; colour is not the only cue | Manual inspection against WCAG 2.1 AA basics |
| NFR-10 | Reliability | Automated test suite passes completely on both SQLite and MySQL | `pytest` output |
| NFR-11 | Maintainability | Code separated into layers; no single-file application | Repository structure |
| NFR-12 | Portability | Runs on Linux and Windows with documented steps | `DEPLOYMENT.md` |
| NFR-13 | Configurability | Security parameters adjustable without code changes | `.env.example`; `flask show-config` |

---

## 8. Feasibility assessment

### 8.1 Technical feasibility — **Feasible, and demonstrated**

Every component is mature, open-source and well documented: Flask, SQLAlchemy,
argon2-cffi, PyOTP, cryptography, Flask-WTF. None required inventing anything.
The one non-trivial design decision — holding the half-authenticated state
server-side rather than in a cookie — is straightforward with a relational
database.

One assumption proved wrong during development and was corrected: Flask's
default session is a *signed client-side cookie*, not server-side storage. Since
the specification requires server-side sessions, a database-backed session store
was implemented (`app/security/server_session.py`). This is recorded in
`TEST_RESULTS.md` §5 as design defect D-01.

### 8.2 Economic feasibility — **Feasible**

| Item | Cost |
|------|------|
| Python, Flask, all libraries | Free (open source) |
| MySQL / MariaDB | Free (community edition) |
| Authenticator apps | Free |
| Development machine | Already owned |
| SMS gateway | **Avoided** by choosing TOTP over SMS |
| **Total** | **Nil beyond existing resources** |

This matters beyond the project: an institution adopting TOTP pays nothing per
authentication, whereas SMS carries a per-message cost that scales with usage.

### 8.3 Operational feasibility — **Feasible, with a caveat**

Users must install an authenticator app and scan a QR code once. This is a real
adoption cost — the main obstacle to MFA rollouts in practice is not technical
but behavioural. The system mitigates it by:

* showing both a QR code and a manually typed key;
* refusing to enable MFA until the user has proved a code works, so nobody is
  locked out by a mis-scan;
* issuing recovery codes immediately, with download and print options;
* keeping MFA optional per account, so adoption can be phased.

The honest caveat: a user who loses both their phone and their recovery codes
needs administrator intervention, and this system documents an identity
verification procedure for that rather than providing a self-service bypass —
because a self-service bypass is exactly the hole an attacker uses.

### 8.4 Schedule feasibility — **Achieved**

The work was organised into the ten phases listed in the project specification,
from analysis through to documentation. All phases were completed; the evidence
is in `PROJECT_EVIDENCE.md`.

### 8.5 Legal and ethical considerations

* **Data minimisation.** The system stores only username, email, optional full
  name, a password hash, an encrypted TOTP secret, recovery-code hashes and
  audit records. No phone number, address, date of birth or any other personal
  data is collected, because none is needed.
* **Audit logs contain personal data** (usernames, IP addresses) and are
  restricted to administrators.
* **Testing was confined to this application on the author's own machine.** No
  third-party system was probed or attacked at any point.
* **Demonstration accounts use reserved example domains** (`example.com`) and
  randomly generated passwords, so no real person's data appears anywhere in
  the repository.

---

## 9. Assumptions and constraints

### Assumptions

1. Users have a device capable of running an authenticator app.
2. Device clocks are within roughly one minute of correct — the ±1 step window
   tolerates ordinary drift.
3. The deployment host keeps reasonably accurate time (NTP).
4. In production the application is served over HTTPS.
5. The `MFA_ENCRYPTION_KEY` is backed up separately from the database; losing
   it means every enrolled user must re-enroll.

### Constraints

1. No SMTP server is available, so password-reset links are displayed on screen
   in demonstration mode instead of being emailed.
2. No external auditor is available, so security testing is self-conducted.
3. Rate limiting uses in-memory storage by default, which is per-process; a
   multi-worker deployment needs a shared store such as Redis, as documented.
4. The project must be demonstrable on a single machine without cloud
   infrastructure.
