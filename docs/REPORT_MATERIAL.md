# Material for the Five-Chapter Academic Report

**Project:** Multi-Factor Authentication (MFA) System for Securing Web Applications
**Student:** Yahye Ahmed Adan · ISBAT University, Kampala

This maps the project onto the standard five-chapter structure and tells you,
for each section, which document to draw from and which figure to cite.

**Two rules for writing the report:**

1. **Describe the system that exists.** Use the same title, objectives,
   terminology, technologies, database design and figures everywhere. The
   single source of truth is [`PROJECT_EVIDENCE.md`](PROJECT_EVIDENCE.md).
2. **Do not invent evidence.** Do not report user-survey responses, participant
   counts, load-test figures or deployment claims that were not produced. What
   *was* produced is substantial and is listed below; it does not need
   embellishing.

---

## Chapter 1 — Introduction

| Section | Source | Notes |
|---------|--------|-------|
| 1.1 Background | `REQUIREMENTS.md` §1 | Why single-factor authentication fails: reuse, breaches, guessing, phishing |
| 1.2 Problem statement | `REQUIREMENTS.md` §1 | The common thread: knowledge of one secret is sufficient |
| 1.3 General objective | `REQUIREMENTS.md` §3 | Use the wording verbatim |
| 1.4 Specific objectives | `REQUIREMENTS.md` §3 | The six objectives, unchanged |
| 1.5 Research questions | Derive from the objectives | See below |
| 1.6 Scope | `REQUIREMENTS.md` §5 | **Include the out-of-scope table** — it shows deliberate boundaries |
| 1.7 Significance | `REQUIREMENTS.md` §8.2 | Nil running cost; no SMS fees; no dependence on a mobile operator |
| 1.8 Limitations | `LIMITATIONS.md` §1 | State the phishing limitation here, early and plainly |
| 1.9 Definitions | Below | |

### Suggested research questions

1. Can a web application enforce a second authentication factor such that a
   valid password alone cannot reach a protected resource?
2. What are the security and usability trade-offs of TOTP compared with SMS,
   email and push-based second factors?
3. How can time-based codes be protected against reuse within their validity
   window?
4. How can authentication secrets be stored so that a database compromise does
   not yield usable credentials?
5. What does TOTP *not* protect against, and what would be required to close
   that gap?

### Terms to define

MFA · Authentication factor (knowledge, possession, inherence) · TOTP · HOTP ·
Argon2id · Salt · Replay attack · Phishing · Credential stuffing · Password
spraying · Session fixation · CSRF · RBAC · Audit log · WebAuthn / passkey

---

## Chapter 2 — Literature Review

| Section | Source | Notes |
|---------|--------|-------|
| 2.1 Authentication factors | `REQUIREMENTS.md` §2 | The three categories |
| 2.2 Password-only authentication | `REQUIREMENTS.md` §2.1 | Structural weakness, not an implementation flaw |
| 2.3 Password storage | `ARCHITECTURE.md` §11 | Plaintext → unsalted hash → salted → memory-hard |
| 2.4 SMS-based OTP | `REQUIREMENTS.md` §2.2 | SIM swap, SS7, NIST deprecation |
| 2.5 Email codes | `REQUIREMENTS.md` §2.3 | A second channel, not a second factor |
| 2.6 TOTP | `REQUIREMENTS.md` §2.4 | RFC 6238; strengths and the phishing gap |
| 2.7 Push approval | `REQUIREMENTS.md` §2.5 | MFA fatigue |
| 2.8 WebAuthn / FIDO2 | `REQUIREMENTS.md` §2.6 | Origin binding is the decisive property |
| 2.9 Comparison | `REQUIREMENTS.md` §2.7 | **Use the comparison table as a figure** |
| 2.10 Gap and justification | `REQUIREMENTS.md` §2.7 | Why TOTP was chosen for this context |

### Standards and sources to cite

* RFC 6238 — TOTP: Time-Based One-Time Password Algorithm
* RFC 4226 — HOTP: HMAC-Based One-Time Password Algorithm
* NIST SP 800-63B — Digital Identity Guidelines (authenticator requirements; restricted status of SMS)
* OWASP Top 10 (current edition) — particularly Broken Access Control and Identification and Authentication Failures
* OWASP Authentication Cheat Sheet; OWASP Password Storage Cheat Sheet
* Argon2 / Password Hashing Competition
* W3C Web Authentication (WebAuthn) Level 2

---

## Chapter 3 — Methodology / System Analysis and Design

| Section | Source | Figure to include |
|---------|--------|-------------------|
| 3.1 Development methodology | `REQUIREMENTS.md`, this file | Incremental, phase-based; each phase verified before the next |
| 3.2 Requirements gathering | `REQUIREMENTS.md` §4, §6, §7 | Stakeholder table; FR and NFR tables |
| 3.3 Feasibility | `REQUIREMENTS.md` §8 | Technical, economic, operational, schedule, legal |
| 3.4 Threat modelling | `THREAT_MODEL.md` | **Trust boundary diagram; STRIDE tables; risk register** |
| 3.5 System architecture | `ARCHITECTURE.md` §1, §2 | **Layered architecture; component diagram** |
| 3.6 Context diagram | `ARCHITECTURE.md` §3 | **Context diagram** |
| 3.7 Data flow diagrams | `ARCHITECTURE.md` §4, §5, §6 | **Level 0 DFD; Level 1 for verification and registration** |
| 3.8 Use cases | `USE_CASES.md` | **Use-case diagram; UC-01 … UC-12** |
| 3.9 Database design | `DATABASE.md` | **ERD; table specifications; normalisation** |
| 3.10 Interface design | `screenshots/` | Wireframe-equivalent screenshots |
| 3.11 Security design | `ARCHITECTURE.md` §10; `THREAT_MODEL.md` §7 | **Design decisions and trade-offs table** |
| 3.12 Tools and technologies | `PROJECT_EVIDENCE.md` §5 | Version table |

**The strongest section here is 3.11.** A decision table that states what was
chosen, what was rejected and what cost was accepted demonstrates engineering
judgement rather than tool assembly.

---

## Chapter 4 — Implementation and Testing

| Section | Source | What to include |
|---------|--------|-----------------|
| 4.1 Development environment | `DEPLOYMENT.md` §1–4 | Setup, configuration, secret generation |
| 4.2 Project structure | `README.md` §5 | The directory tree with the layer explanation |
| 4.3 Database implementation | `DATABASE.md`; `diagrams/schema_mysql.sql` | Migration output; the exported schema |
| 4.4 Password security | `app/security/passwords.py` | Argon2id parameters; **the predictability check and why composition rules alone are inadequate** |
| 4.5 TOTP implementation | `app/security/totp.py` | **Code excerpt of `verify_code`; the window and replay reasoning** |
| 4.6 Secret encryption | `app/security/crypto.py` | Fernet; why the key lives outside the database |
| 4.7 The two-step flow | `ARCHITECTURE.md` §7, §8 | **Sequence diagram; three-state machine** |
| 4.8 Recovery codes | `app/security/recovery.py` | Generation, hashing, single use |
| 4.9 Access control | `app/security/access.py` | The decorators; server-side enforcement |
| 4.10 Audit logging | `app/security/audit.py` | **The scrubber; the structural absence of secret columns** |
| 4.11 User interface | `screenshots/` | Selected screenshots with commentary |
| 4.12 Test strategy | `TEST_PLAN.md` | Levels, environment, measurement procedures |
| 4.13 Test results | `TEST_RESULTS.md` | **219/219 on both backends; 88 % coverage** |
| 4.14 Defects found and fixed | `TEST_RESULTS.md` §5 | **Include this — see below** |
| 4.15 Performance | `TEST_RESULTS.md` §6 | Response times; hashing cost; timing equalisation |
| 4.16 Deployment | `DEPLOYMENT.md` | Gunicorn, MySQL, verified headers |

### Why section 4.14 matters

A project that reports no defects invites the question of how hard anyone
looked. Seven were found, and three of them are genuinely interesting to write
about:

* **D-01** — the discovery that Flask's default session is a *client-side*
  signed cookie, which failed the server-side requirement and was putting
  plaintext recovery codes in the browser's cookie jar. Fixed by implementing a
  database-backed session store.
* **D-02** — the account-enumeration timing defence that did not work, because
  the placeholder hash was malformed and argon2-cffi rejected it in
  microseconds instead of spending ~120 ms. Found by *measuring* rather than by
  reading the code; the measurement before and after is good evidence.
* **D-03** — the password policy accepting `Password123!`, which satisfies every
  composition rule and is one of the most common passwords in existence. Fixed
  by undoing the mangling attackers already automate before consulting the
  blocklist.

Each of these shows the testing process doing its job, and each has a
before-and-after measurement or test to cite.

### Code excerpts worth including

| Excerpt | Why |
|---------|-----|
| `verify_code()` in `security/totp.py` | The replay-prevention logic, with the reasoning in its docstring |
| `complete_login()` in `security/session.py` | The single place a full session is created |
| `login_required` in `security/access.py` | Where the MFA bypass is prevented |
| `record_event()` and `scrub()` in `security/audit.py` | How secrets are kept out of the log |
| `dummy_hash()` in `security/passwords.py` | The timing defence, and the comment explaining the bug it replaced |
| The login view in `auth/routes.py` | The ordered checks, with the reasoning for the order |

---

## Chapter 5 — Results, Discussion and Conclusion

| Section | Source | Notes |
|---------|--------|-------|
| 5.1 Summary of findings | `TEST_RESULTS.md` §1 | The headline figures |
| 5.2 Objectives achieved | `LIMITATIONS.md` §6 | **Objective 6 is "partly": deployed locally, not publicly. Say so** |
| 5.3 Acceptance criteria | `TEST_RESULTS.md` §8 | 12 of 12, with the evidence for each |
| 5.4 Discussion | Below | |
| 5.5 Limitations | `LIMITATIONS.md` | **Do not shorten this section** |
| 5.6 Future work | `LIMITATIONS.md` §7 | WebAuthn first, with the reason |
| 5.7 Conclusion | `LIMITATIONS.md` §8 | |

### Points worth discussing in 5.4

**What the evidence actually establishes.** The central claim — that a password
alone cannot reach a protected page on an MFA-enabled account — is supported
from three independent directions: unit tests of the verification logic,
integration tests of the HTTP flow, and a browser-driven system test against
MySQL under Gunicorn. Screenshot `16-bypass-attempt-blocked.png` shows it
happening.

**The cost of security is measurable, and small.** Argon2id costs about 120 ms
per login. A user notices nothing. An offline attacker is limited to roughly
eight guesses per second per core, and the 64 MiB memory requirement blunts GPU
parallelisation. That is a good trade, and it is quantified rather than
asserted.

**Composition rules are a weak control on their own.** `Password123!` satisfies
every rule this project started with — twelve characters, four character
classes — and is among the most common passwords in the world. Defect D-03 is
a concrete demonstration that password policies must model what attackers
actually do, not just count character classes.

**Measuring a control is not the same as implementing it.** Defect D-02 is the
clearest example: the timing defence looked right in the code and did nothing
in practice. It was found by measuring, not by reading. This is a general
lesson worth drawing out — security controls need empirical verification.

**Usability and security genuinely conflict here, and the conflict is visible.**
Replay prevention means a user cannot sign in twice within the same 30-second
step. Recovery codes are shown exactly once because only hashes are stored. A
password reset does not disable MFA, which is safer but leaves a user who has
lost both factors needing an administrator. Each of these is a deliberate
choice with a cost, and the report is stronger for naming the cost.

**Adoption is the limiting factor, not the mechanism.** The admin dashboard's
MFA adoption percentage is the most important number on it. A perfectly
implemented second factor protects nobody who has not enabled it. This is why
the system prompts persistently, proves the code works before switching
anything on, and issues recovery codes automatically.

### What **not** to write

* Any number of test users, survey responses or satisfaction ratings — none were
  collected.
* Any throughput or concurrent-user figure — no load testing was performed.
* Any claim of production deployment — the deployment was local and controlled.
* Any claim of phishing resistance — TOTP does not provide it.
* Any claim that the system is secure against all attacks — `LIMITATIONS.md`
  §2 lists what it cannot address.

---

## Figures and tables to include

| # | Figure | Source |
|---|--------|--------|
| 1 | Comparison of authentication methods | `REQUIREMENTS.md` §2.7 |
| 2 | Trust boundary diagram | `THREAT_MODEL.md` §2 |
| 3 | Risk register | `THREAT_MODEL.md` §5 |
| 4 | Layered architecture | `ARCHITECTURE.md` §1 |
| 5 | Component diagram | `ARCHITECTURE.md` §2 |
| 6 | Context diagram | `ARCHITECTURE.md` §3 |
| 7 | Level 0 DFD | `ARCHITECTURE.md` §4 |
| 8 | Level 1 DFD — second-factor verification | `ARCHITECTURE.md` §5 |
| 9 | Authentication sequence diagram | `ARCHITECTURE.md` §7 |
| 10 | Three-state authentication machine | `ARCHITECTURE.md` §8 |
| 11 | Entity-relationship diagram | `DATABASE.md` §1 |
| 12 | Use-case diagram | `USE_CASES.md` §1 |
| 13 | Design decisions and trade-offs | `ARCHITECTURE.md` §10 |
| 14 | Security control parameters | `PROJECT_EVIDENCE.md` §6 |
| 15 | Test results summary | `TEST_RESULTS.md` §1 |
| 16 | Coverage by module | `TEST_RESULTS.md` §3.4 |
| 17 | Performance measurements | `TEST_RESULTS.md` §6 |
| 18 | Defects found and fixed | `TEST_RESULTS.md` §5 |
| 19 | Acceptance criteria verdict | `TEST_RESULTS.md` §8 |
| 20–30 | Screenshots | `screenshots/INDEX.md` |

---

## Appendices

| Appendix | Contents | Source |
|----------|----------|--------|
| A | Full source listing, or selected modules | `app/` |
| B | Database schema | `diagrams/schema_mysql.sql` |
| C | Test plan | `TEST_PLAN.md` |
| D | Complete test output | `TEST_RESULTS.md` |
| E | All screenshots | `screenshots/` |
| F | Installation and deployment guide | `DEPLOYMENT.md` |
| G | User manual | `USER_MANUAL.md` |
| H | Administrator guide | `ADMIN_GUIDE.md` |
| I | Configuration template | `.env.example` |
| J | Dependencies with versions | `requirements.txt` |

---

## Consistency checklist before submission

- [ ] The project title is identical on the cover, in the abstract and in every chapter
- [ ] The six specific objectives are worded identically wherever they appear
- [ ] Technology versions match `PROJECT_EVIDENCE.md` §5 throughout
- [ ] Test figures match `TEST_RESULTS.md` — **219 tests, 88 % coverage**, not rounded differently in different places
- [ ] Every screenshot referenced exists in `screenshots/` and is numbered as in `INDEX.md`
- [ ] Database tables described match the eight in `DATABASE.md`
- [ ] The phishing limitation appears in Chapter 1, Chapter 5 and the abstract
- [ ] No claim of a user study, load test or public deployment appears anywhere
- [ ] Every diagram is referenced in the text, not merely inserted
- [ ] The declaration states that all testing was confined to the author's own system
