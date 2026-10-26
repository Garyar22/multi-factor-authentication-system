# Security Limitations and Future Improvements

**Project:** Multi-Factor Authentication (MFA) System for Securing Web Applications
**Student:** Yahye Ahmed Adan · ISBAT University, Kampala

A security system that claims to solve everything is not trustworthy. This
document states what this project does **not** do. For an academic project it
is as important as the feature list: a marker can verify a working control, but
only honesty can establish the boundaries.

---

## 1. The most important limitation: TOTP is not phishing-resistant

### The attack

An attacker builds a convincing replica of the sign-in page and gets the victim
there — a link in an email, a lookalike domain, a sponsored search result.

1. The victim enters their username and password. The attacker's server
   captures them and immediately submits them to the real site.
2. The real site responds asking for a code. The attacker's page asks the
   victim for a code.
3. The victim reads the current code from their authenticator app and types it.
4. The attacker relays that code to the real site **within its validity
   window** and receives a genuine session.

The victim sees a plausible page and suspects nothing.

### Why TOTP cannot prevent this

A TOTP code is derived from a shared secret and the current time. It is **not
bound to the website the user is actually talking to**. A valid code is valid
wherever it is typed, so relaying it works.

This is not a flaw in this implementation. It is inherent to the TOTP scheme,
and it applies equally to every TOTP deployment anywhere.

### What this system does do

* The replay guard means a captured code is useless once the legitimate user
  has used it, which closes the simpler variant of the attack.
* The short window limits how long a captured code remains useful.
* The audit log records the source address, so the intrusion is visible
  afterwards.
* The user manual tells users plainly to check the address bar before typing a
  code, and that nobody legitimate will ever ask them for one.

None of that stops a competent real-time proxy. **This is an accepted,
documented limitation, and the project does not claim otherwise.**

### What would fix it: WebAuthn / passkeys

WebAuthn uses public-key cryptography, and the browser binds the signature to
the **origin** of the site requesting it. A signature produced at
`evil-example.com` is worthless at `mfa.example.ac.ug`, because the browser
simply will not produce one for the wrong origin. Phishing stops working — not
because the user is more careful, but because the protocol makes it impossible.

**Why it was not implemented here:** correctly implementing WebAuthn —
registration ceremony, attestation, assertion verification, credential storage,
cross-device recovery — is a project in itself. Implementing it badly would be
worse than implementing TOTP well. TOTP meets the stated objectives; WebAuthn
is recorded as the primary future enhancement (§7.1).

---

## 2. Threats outside this system's reach

### 2.1 A compromised user device

Malware with control of the user's computer or phone can read the password as
it is typed, read codes from the screen, or hijack a session that has already
been established. No server-side authentication control can repair a
compromised endpoint.

### 2.2 A compromised server

Every protection here assumes the application server is not under an attacker's
control. An attacker with code execution on that host has the encryption key,
the session store and the database together.

### 2.3 Supply-chain compromise

A malicious release of any dependency could undermine the whole system.
Partially mitigated by pinning exact versions in `requirements.txt`, so an
unexpected change is at least visible — but pinning does not detect a
compromised version that was pinned deliberately.

### 2.4 Social engineering of the administrator

The weakest link in most MFA deployments is the help desk. `ADMIN_GUIDE.md` §7
sets out an out-of-band identity verification procedure and deliberately
provides **no** one-click MFA reset, but a procedure is only as strong as the
person following it under pressure.

### 2.5 Network-level denial of service

Volumetric attacks need infrastructure-level defences — a CDN, a scrubbing
service, rate limiting at the edge — which are outside an application project.

---

## 3. Implementation limitations

### 3.1 Password reset links are displayed, not emailed

**The limitation.** No SMTP server was available, so after a reset request the
link is shown on screen rather than sent by email.

**Why this is acceptable here.** The complete token lifecycle — generation,
SHA-256 storage, expiry, single use, invalidation of earlier tokens, and the
refusal to disable MFA — is fully implemented and tested. Only the delivery
channel is missing.

**Why it would be unacceptable in production.** Anyone who could request a
reset would see the link, which is a complete account takeover for any account
without MFA.

**Mitigations present:** the page states plainly that this is demonstration
behaviour; the identical response for known and unknown addresses means the
form cannot be used to enumerate accounts; and **a reset still does not disable
MFA**, so an MFA-enabled account survives this weakness.

**The fix:** configure Flask-Mail or an email API, send the link, and remove
the on-screen display. Roughly an hour's work, gated on having a mail server.

### 3.2 Rate limiting is per-process by default

`memory://` storage means each Gunicorn worker counts independently. With three
workers, an attacker effectively gets three times the configured allowance.

**Mitigations:** per-account lockout is stored in the database and is therefore
shared across workers, so the most important control is unaffected. The fix is
one configuration line — `RATELIMIT_STORAGE_URI=redis://...` — documented in
`DEPLOYMENT.md`.

### 3.3 Rate limiting is per-IP, so it is distributable

An attacker with a botnet spreads attempts across thousands of addresses and
stays under the per-IP limit. Per-account lockout still applies, and the admin
dashboard surfaces the cross-account pattern — but that is **detection, not
prevention**. Serious defence against distributed credential stuffing needs
device fingerprinting, reputation data or a CAPTCHA, all out of scope.

### 3.4 The audit log is append-only by convention

The application only inserts and selects, and `DEPLOYMENT.md` §9 documents
revoking UPDATE and DELETE from the runtime database account. But an attacker
with MySQL administrative access, or host access, can still alter the table.

Genuine tamper-evidence requires shipping logs to a separate host, or hash
chaining each record to the previous one. Both are future work (§7.5).

### 3.5 Recovery codes exist briefly as plaintext in the session row

Between generation and display, the ten codes are held in the server-side
session so that the page can show them and the download can work. They are
cleared on download or when the user confirms they have saved them, and the
session itself expires.

This is a deliberate trade-off, and much better than the alternative that was
originally implemented — holding them in a client-side cookie, which sent them
to the browser's cookie jar (recorded as defect D-01 in `TEST_RESULTS.md`).
Eliminating the window entirely would mean streaming the codes to the browser
without any server-side copy, which breaks the download button.

### 3.6 No account-lockout notification

A user whose account is locked by someone else's failed attempts is not told.
They discover it when they try to sign in. An email alert would be better, and
needs the mail infrastructure of §3.1.

### 3.7 Deliberate lockout can deny service

Anyone who knows a username can lock that account by failing five times.
Inherent to any lockout mechanism. Mitigated by making the lockout
time-limited (15 minutes) rather than permanent, and by letting an
administrator clear it. The alternative — no lockout — is worse.

### 3.8 One second-factor method

Only TOTP. No hardware key, no backup method beyond recovery codes. The
`mfa_credentials.method` column exists so a second method could be added
without a schema change, but no second method is implemented.

### 3.9 No password history

A user can change their password back to the previous one immediately.
Preventing that means storing old hashes, which has its own privacy
implications and needs a policy decision about how many to keep.

### 3.10 No breached-password check

The policy rejects a curated list of common passwords and the mangling patterns
around them, which catches the obvious cases. It does not check against a real
breach corpus. The Have I Been Pwned range API would do this with k-anonymity
(only the first five characters of the SHA-1 hash leave the server), and is a
modest addition — see §7.4.

### 3.11 Session fingerprinting is recorded but not enforced

`server_sessions` stores the IP address and user agent, but the system does not
refuse a session that suddenly appears from a different address. Enforcing it
would catch some session theft, at the cost of breaking legitimate users who
move between Wi-Fi and mobile data — a real problem where connectivity is
intermittent. Recorded rather than enforced was the deliberate choice.

### 3.12 CLI test coverage is 35 %

The command-line commands are exercised manually rather than by the suite.
Every command was actually run during deployment (`TEST_RESULTS.md` §7), but
they are not protected against regression by automated tests.

---

## 4. Usability limitations

### 4.1 No login twice within the same 30-second step

Replay prevention burns the time step of each accepted code, so a user who
signs in, signs out and signs straight back in must wait for the next code.
This is security working as intended, and it is documented in the user manual
and in the troubleshooting guide — but it does surprise people.

### 4.2 Clock drift causes confusing failures

If the phone's clock is wrong by more than about a minute, every code is
refused with no explanation of why. The system cannot diagnose this, because
from the server's point of view the codes are simply wrong. Mitigated only by
documentation.

### 4.3 Enrollment requires a second device

A user without a smartphone cannot enrol, unless they use a desktop
authenticator. In contexts where smartphone access is uneven this is a real
barrier — and it is part of why SMS, for all its weaknesses, remains in use.

### 4.4 Recovery codes are shown exactly once

A user who closes the page without saving them has lost them permanently and
must generate a new set. This follows directly from storing only hashes, which
is the right trade — but it is a usability cost, mitigated by prominent
download, print and confirm options.

---

## 5. Scope limitations

| Not implemented | Reason |
|-----------------|--------|
| WebAuthn / passkeys | Time; see §7.1 |
| SMS or voice OTP | Deliberately rejected: SIM swap, SS7, cost |
| Push approval | MFA fatigue; third-party dependency |
| Biometrics | Device hardware and data-protection complexity |
| Single sign-on, OAuth, SAML | Different problem domain |
| Risk-based / adaptive authentication | Needs behavioural data and tuning |
| Multi-tenancy | Not required |
| Internationalisation | English only |
| Email notifications | No mail server |
| Account deletion / data export | Would be required under a data-protection regime; not required for this project |

---

## 6. Honest evaluation against the objectives

| Objective | Achieved? | Qualification |
|-----------|-----------|---------------|
| 1. Study existing authentication systems | **Yes** | Six approaches compared with reasons for the choice |
| 2. Analyse password-only risks | **Yes** | Full STRIDE analysis and risk register |
| 3. Design an MFA architecture | **Yes** | Layered design, diagrams, documented trade-offs |
| 4. Develop a web-based MFA system | **Yes** | Working application on the specified stack |
| 5. Implement and test controls | **Yes** | 219 automated tests on two backends, 88 % coverage, measured performance |
| 6. Deploy and evaluate | **Partly** | Deployed and evaluated in a **controlled local environment** under Gunicorn with MySQL. Not deployed to a public internet-facing server with real users, so no claim is made about behaviour under real-world load or attack |

### What this project demonstrably achieves

* A password alone cannot reach a protected page on an MFA-enabled account —
  verified from several directions, including with a real browser against MySQL.
* Reused and replayed codes are refused.
* Recovery codes work once and only once.
* No authentication secret reaches any log.
* Authorisation is enforced server-side on every protected operation.
* A database dump alone does not yield usable credentials or TOTP seeds.

### What it does not demonstrate

* Resistance to real-time phishing.
* Behaviour under production load or a real attack.
* Security against an attacker with server or endpoint access.
* Findings from an independent security review.

---

## 7. Future improvements, in priority order

### 7.1 WebAuthn / passkeys — **highest priority**

Adds the phishing resistance TOTP structurally cannot provide. The
`mfa_credentials.method` column was included with this in mind, so a
`webauthn` credential type could sit alongside `totp` without a schema change.
Estimated effort: 2–3 weeks, including recovery flows.

### 7.2 Email notification and delivery

Send reset links rather than displaying them, and notify users of: a new
sign-in from an unfamiliar address, MFA being disabled, a password change, and
an account lockout. Several of these are genuine security controls, not
conveniences — a "your MFA was disabled" email is often how a victim discovers
an intrusion. Estimated effort: 3–5 days.

### 7.3 Risk-based step-up authentication

Require the second factor only when the sign-in looks unusual — new device, new
location, unusual hour — and skip it on a recognised device. Reduces friction,
which raises adoption, which is what actually improves overall security.
Estimated effort: 1–2 weeks.

### 7.4 Breached-password checking

Query the Have I Been Pwned range API with the first five characters of the
SHA-1 hash, so the password itself never leaves the server. Would catch
compromised passwords that are not on any curated list. Estimated effort:
1 day.

### 7.5 Tamper-evident audit logging

Hash-chain each audit record to its predecessor so any alteration is
detectable, and ship logs to a separate host. Estimated effort: 3–5 days.

### 7.6 Administrative MFA reset with a proper workflow

A controlled in-application flow — request, second administrator's approval,
mandatory reason, full audit trail — rather than the manual SQL procedure of
`ADMIN_GUIDE.md` §7. Would make the dangerous operation both easier and safer,
because it would be recorded. Estimated effort: 1 week.

### 7.7 Operational improvements

* Shared rate-limit storage as the default
* Password history
* Optional session binding to IP or device, with sensible handling of roaming
* Account deletion and data export
* Internationalisation, including Somali and Swahili

---

## 8. Conclusion

This project delivers a working multi-factor authentication system that
measurably achieves its central objective: **a stolen password is not enough to
reach a protected resource on an MFA-enabled account.** That claim is
substantiated by 219 automated tests on two database backends, an end-to-end
system test with a real browser against MySQL, and 33 screenshots of the
running application.

It does not solve authentication. TOTP leaves real-time phishing open, and that
limitation is inherent rather than accidental. The honest summary is that this
system raises the cost of the common, high-volume attacks — credential
stuffing, password spraying, offline cracking after a breach — from trivial to
impractical, while leaving targeted real-time phishing unaddressed.

That is a worthwhile improvement, and stating its boundary precisely is part of
the work rather than a weakness in it.
