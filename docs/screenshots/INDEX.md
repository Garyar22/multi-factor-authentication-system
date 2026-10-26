# Screenshot Index

**Multi-Factor Authentication System** · Yahye Ahmed Adan · ISBAT University

All 33 images were **captured from the running application** on 23 October 2026
by driving a real Chromium browser against the system served by Gunicorn on
MySQL (MariaDB 10.11.14). None is a mock-up, a wireframe or an edited image.

| Property | Value |
|----------|-------|
| Captured | 23 October 2026 |
| Application version | 1.0.0 |
| Server | Gunicorn 26.2.0, 2 workers |
| Database | MariaDB 10.11.14 |
| Browser | Chromium via Playwright |
| Desktop viewport | 1366 × 900 |
| Mobile viewport | 390 × 844 |

---

## User registration and sign-in

| File | Shows | Cite for |
|------|-------|----------|
| `01-landing-page.png` | Project landing page: the five-step explanation of how signing in works, the six security features, and the honest scope statement about phishing | Ch. 4 — interface design |
| `02-registration-empty.png` | Empty registration form with the password rule checklist | FR-01, Ch. 4 |
| `03-registration-filled-strength-meter.png` | Form completed, strength meter filled, all five rules ticked | FR-03, usability |
| `04-registration-success.png` | Account created; the user is invited to enable two-step verification | FR-01 |
| `05-weak-password-rejected.png` | **`Password123!` rejected as too predictable** — it satisfies every composition rule and is still refused | FR-03, defect D-03 |
| `06-login-step1.png` | Sign-in page with the two-step progress trail showing step 1 of 2 | FR-08 |
| `07-login-generic-error.png` | **Generic "Invalid credentials" message** — identical whether the username exists or not | FR-09, account enumeration |
| `08-dashboard-mfa-off.png` | Dashboard for an account without MFA: the prominent warning that only one factor protects it | FR-31 |

---

## MFA enrollment

| File | Shows | Cite for |
|------|-------|----------|
| `09-security-settings-mfa-off.png` | Security settings before enrollment, explaining the risk of a password alone | FR-15 |
| `10-mfa-enrollment-qr.png` | **Enrollment page: a real scannable QR code, the base32 key for manual entry, and the parameters (6 digits, 30 s)** | **FR-16, FR-17 — the key enrollment evidence** |
| `11-enrollment-wrong-code-rejected.png` | A wrong code at enrollment is refused and **MFA stays off** — this is what stops a mis-scan locking a user out | FR-18 |
| `12-recovery-codes-shown-once.png` | **Ten single-use recovery codes, displayed once**, with download, print and "I have saved these" | FR-24, FR-25 |
| `13-security-settings-mfa-on.png` | Settings with MFA enabled: unused code count, encryption at rest, replay protection | FR-19, FR-21 |

---

## Two-step login and MFA enforcement — **the central evidence**

| File | Shows | Cite for |
|------|-------|----------|
| `14-protected-resources.png` | Protected sample documents, reachable only with a full session | FR-31 |
| `15-mfa-verify-step2.png` | **Second-factor prompt after a correct password** — the progress trail shows step 1 complete, step 2 current | **FR-12, acceptance criterion 3** |
| `16-bypass-attempt-blocked.png` | **A direct request for `/dashboard` while half-authenticated, landing back on the verification page.** The URL bar is the proof: the browser asked for the dashboard and was sent to `/mfa/verify` | **Acceptance criterion 3 — the project's central claim** |
| `17-invalid-code-rejected.png` | Wrong code refused; no session granted | FR-20 |
| `18-dashboard-mfa-on.png` | Dashboard after a complete two-step sign-in, showing recent security activity | FR-12 |
| `19-access-denied-403.png` | **A standard user requesting `/admin/` receives 403** — authorisation enforced server-side | FR-34, acceptance criterion 7 |

---

## Recovery and password reset

| File | Shows | Cite for |
|------|-------|----------|
| `20-recovery-code-prompt.png` | Recovery-code entry for a user without their device | FR-27 |
| `21-recovery-code-accepted.png` | Signed in with a recovery code; the remaining count is reported | FR-27 |
| `22-recovery-code-reuse-refused.png` | **The same recovery code refused on a second attempt** | **FR-27, acceptance criterion 5** |
| `23-forgot-password.png` | Reset request page, noting that a reset does **not** disable MFA | FR-30 |
| `24-reset-link-generated.png` | Reset link generated, with the **demonstration-mode notice** explaining that a real deployment would email it | FR-29, limitation §3.1 |
| `25-set-new-password.png` | Setting a new password, with the policy applied again | FR-29 |
| `26-error-404.png` | Friendly error page with no traceback or framework internals | NFR, TC-110 |

---

## Administration

| File | Shows | Cite for |
|------|-------|----------|
| `27-admin-dashboard.png` | **Administrator dashboard with live statistics**: MFA adoption, 24-hour authentication activity, replayed codes blocked, failed-login hotspots by username and source address, and the most recent security events | FR-37, Ch. 4 |
| `28-admin-user-management.png` | User list with status, MFA state, failure counts, and the activate / deactivate / unlock controls | FR-35, FR-36 |
| `29-admin-audit-log.png` | **Full audit log** showing the real event trail, with the note on what it deliberately never contains | FR-39 – FR-45 |
| `30-audit-filter-replay-blocked.png` | Audit log filtered to `mfa_verify_replay_rejected` — **evidence that replay prevention fired in the live system** | FR-21, acceptance criterion 4 |

---

## Responsive design

| File | Shows | Cite for |
|------|-------|----------|
| `32-mobile-landing.png` | Landing page at 390 × 844: no horizontal scroll, readable text, usable buttons | NFR-08 |
| `33-mobile-login.png` | Sign-in at mobile width | NFR-08 |
| `34-mobile-register.png` | Registration at mobile width, with the strength checklist intact | NFR-08 |

---

## Suggested selection for the report

A report rarely has room for all 33. If you need a short set, these ten carry
the argument:

| Priority | File | Why it earns the space |
|---------:|------|------------------------|
| 1 | `16-bypass-attempt-blocked.png` | Proves the central claim: password alone does not reach a protected page |
| 2 | `10-mfa-enrollment-qr.png` | Shows the enrollment mechanism working |
| 3 | `15-mfa-verify-step2.png` | Shows the second-factor step in the real flow |
| 4 | `12-recovery-codes-shown-once.png` | Shows the recovery mechanism |
| 5 | `22-recovery-code-reuse-refused.png` | Proves single use |
| 6 | `30-audit-filter-replay-blocked.png` | Proves replay prevention fired in the live system |
| 7 | `19-access-denied-403.png` | Proves server-side authorisation |
| 8 | `27-admin-dashboard.png` | Shows the administrative capability |
| 9 | `05-weak-password-rejected.png` | Shows the password policy doing real work |
| 10 | `32-mobile-landing.png` | Evidences responsive design |

---

## A note on numbering

The sequence runs 01–30 and 32–34. Number 31 was to be an administrator's view
of an individual user's detail page; the automated capture did not match the
link selector on that run, so no image was produced. The gap is left in place
rather than renumbering, because renumbering would make every reference in the
report that was already written point at the wrong image. The page itself
exists and works — it is `/admin/users/<id>`, shown in
`app/templates/admin/user_detail.html` and covered by tests in
`tests/test_models_and_admin.py`.
