# Administrator Guide

**Multi-Factor Authentication System**
ISBAT University · Yahye Ahmed Adan

---

## 1. What an administrator can and cannot do

Being clear about the boundary matters, because users will ask for things that
are deliberately impossible.

### Can

* View all registered accounts and their status
* Search accounts by username, email or name
* Activate and deactivate accounts
* Clear a lockout caused by failed sign-ins
* View the complete security audit log, with filters
* View authentication statistics and failed-login patterns
* View any individual account's security event history

### Cannot — by design

| Not possible | Why |
|--------------|-----|
| Read a user's TOTP secret | Stored encrypted, and no interface decrypts it for display |
| Read a user's recovery codes | Only hashes are stored; nothing can reverse them |
| Reset or remove a user's MFA | A self-service or one-click admin bypass is the most commonly exploited weakness in MFA deployments. Section 7 sets out the controlled procedure |
| Sign in as another user | No impersonation function exists |
| Read or change a password | Only the Argon2id hash is stored |
| Edit or delete audit records | The application only inserts and reads. `DEPLOYMENT.md` §9 documents revoking UPDATE and DELETE at the database level |

If a user asks you to "just turn off MFA for me", section 7 is the answer.

---

## 2. Getting started

### Creating the first administrator

```bash
flask --app wsgi create-admin --username sysadmin --email admin@yourdomain.example
```

You are prompted for a password, which is never displayed or stored in a file.
There is **no default administrator password** in this project.

### Turn on two-step verification for your own account immediately

An administrator account protected by a password alone is the most valuable
target in the system. Sign in, go to **Security**, and enrol. Save the recovery
codes somewhere separate from your phone.

### Creating further administrators

Run `create-admin` again. There is deliberately no way to promote an account
through the web interface — privilege escalation through a web form is a common
attack path, so the only route is command-line access to the server.

---

## 3. The administrator dashboard

**Screenshot 27.** Reached from **Admin** in the top bar.

### Accounts

| Figure | Meaning | What to watch for |
|--------|---------|-------------------|
| Registered users | Total accounts | Sudden growth may mean automated registration |
| Active accounts | Not deactivated | |
| **MFA adoption** | Percentage with two-step verification on | **The single most useful number here.** Low adoption means most accounts are one password away from compromise |
| Currently locked out | Accounts in lockout now | Several at once suggests an attack in progress |

### Authentication activity, last 24 hours

| Figure | Meaning | What to watch for |
|--------|---------|-------------------|
| Successful sign-ins | Completed logins | Activity at unusual hours |
| Failed sign-ins | Rejected attempts | A sharp rise, especially spread across many usernames |
| Codes verified | Successful second factors | |
| Codes rejected | Failed second factors | Many for one user who has not reported a problem may mean someone has their password and is stuck at the second factor — **good news about the control, bad news about the password** |

### Security controls in effect

| Figure | Meaning |
|--------|---------|
| **Replayed codes blocked** | Codes presented a second time and refused. A non-zero value means either a user double-submitting, or someone attempting to reuse an observed code |
| Recovery codes used | Each one means a user signed in without their device. Worth a check that it was really them |
| Access denied | Attempts to reach pages the requester was not entitled to |

### Failed sign-in hotspots

Two tables show the usernames and source addresses with the most failures in
the last 24 hours. Read them together:

* **One username, many failures, one address** — probably that user struggling,
  or a targeted attack on them
* **Many usernames, few failures each, one address** — **password spraying**
* **One username, many failures, many addresses** — a distributed attack on one
  account, usually a privileged one
* **Usernames that do not exist** — someone probing to find valid accounts

---

## 4. Managing accounts

**Screenshots 28, 31.** **Admin → Manage users.**

Each row shows username, email, role, status, whether MFA is on, the current
failed-login count and the last sign-in time.

### Deactivating an account

Choose **Deactivate**. This:

* blocks all future sign-ins;
* **immediately deletes every active session for that user**, so they are
  signed out everywhere at once rather than keeping access until their session
  expires;
* records the action with your administrator id;
* reports how many sessions were revoked.

Use it when someone leaves, or when you suspect an account is compromised.

**Two things the system will refuse:**

* deactivating your own account;
* deactivating the last active administrator.

Both exist to stop the deployment being locked out of its own administration.

### Reactivating

Choose **Activate**. The user's password, MFA setup and recovery codes are
untouched and still work.

### Clearing a lockout

Choose **Unlock**. This clears the lockout and resets the failure counter.

Before you do, ask yourself why the account locked. If the user says they were
not trying to sign in, **somebody else was** — tell them to change their
password and, if they have not already, to enable two-step verification.

---

## 5. The audit log

**Screenshots 29, 30.** **Admin → Audit log.**

### Event types

| Event | Meaning |
|-------|---------|
| `register_success` / `register_failed` | Account creation |
| `login_success` | Full authentication completed |
| `login_failed` | Wrong password, or unknown username |
| `login_blocked_locked` | Attempt while locked out |
| `login_blocked_inactive` | Attempt on a deactivated account |
| `login_rate_limited` | Too many attempts from one address |
| `account_locked` | Lockout threshold reached |
| `logout` | User signed out |
| `mfa_step_required` | Password accepted; second factor demanded |
| `mfa_verify_success` | Second factor accepted |
| `mfa_verify_failed` | Wrong code |
| **`mfa_verify_replay_rejected`** | **A valid code presented a second time, and refused** |
| `mfa_pending_expired` | Too many wrong codes; half-authenticated state destroyed |
| `mfa_enroll_started` / `_completed` / `_failed` | Enrollment lifecycle |
| `mfa_disabled` | Two-step verification turned off |
| `mfa_recovery_codes_generated` | A new set issued |
| `mfa_recovery_code_used` / `_failed` | Recovery-code sign-in |
| `password_reset_requested` / `_completed` / `_invalid_token` | Reset lifecycle |
| `password_changed` | Password changed while signed in |
| `access_denied` | Request for a page the requester was not entitled to |
| `admin_*` | Administrative actions, with the acting administrator recorded |

### What the log never contains

No row ever holds a password, a submitted one-time code, a recovery code, a
reset token or a session identifier. Values of that shape are stripped before
an event is written, and the table has no column that could hold one.

**The practical consequence:** this log can be shared with an investigator, or
kept for a long period, without becoming a credential store itself.

### Reading the log during an investigation

Filter by event type, outcome or category. A useful sequence when investigating
a suspected compromise:

1. Filter `login_success` and look for unfamiliar source addresses.
2. Filter `mfa_verify_failed` for that user — many failures before a success
   suggests someone was guessing.
3. Check `mfa_recovery_code_used` — did they use a recovery code they do not
   remember using?
4. Check `mfa_disabled` — was the second factor removed, and when?
5. Check `password_reset_completed` — was a reset performed that the user did
   not request?
6. Open the user's detail page for their complete history in one place.

---

## 6. Responding to common situations

### A user cannot sign in

1. Check **Manage users**: is the account active? Is it locked?
2. If locked, find out *why* before unlocking.
3. If they reach the code step but the code is refused, it is almost always the
   clock on their phone — see `USER_MANUAL.md` §8.
4. If they have lost their device, section 7.

### Many failed sign-ins from one address

1. Open the dashboard and read both hotspot tables.
2. If it is spread across many usernames, it is password spraying. Rate
   limiting is already slowing it; consider blocking the address at the
   firewall or reverse proxy.
3. Check whether any attempt succeeded. If one did, deactivate that account
   immediately and contact the user.
4. Encourage MFA enrollment — it is what turns a successful password guess into
   a dead end.

### Replayed codes appearing in the log

A small number is usually a user double-clicking. A pattern for one user,
especially from an unfamiliar address, suggests someone is capturing and
reusing codes. Contact the user, and consider deactivating the account while
you investigate.

### A suspected account compromise

1. **Deactivate the account** — this also revokes every live session at once.
2. Review that user's full event history on their detail page.
3. Note the source addresses involved.
4. Contact the user through a channel other than the system.
5. Once their identity is verified: reactivate, have them change their password,
   have them generate new recovery codes, and if MFA was disabled during the
   incident, have them enrol again.
6. Keep a record. The audit log is your evidence.

---

## 7. MFA reset — the controlled procedure

**This is the most sensitive thing you will do.** An attacker who persuades you
to reset a victim's MFA has bypassed the entire system. Attackers know this,
and help desks are where MFA deployments usually fail. Follow the procedure
even when it feels excessive, and especially when the person is in a hurry —
urgency is a standard pressure tactic.

### Before doing anything

1. **Verify identity out of band.** Not by replying to the email that asked.
   Call a number already on file, or meet in person. A request that arrives by
   email and asks you to reply to that same email verifies nothing.
2. **Ask for something only the real user would know** — their last sign-in
   time, recent activity, details from their enrollment.
3. **Check the audit log.** Does the story fit? If they say they lost their
   phone yesterday but there were successful sign-ins this morning, stop.
4. **Be suspicious of urgency**, especially for a privileged account.

### Carrying it out

There is deliberately no button for this. If, after verification, a reset is
genuinely needed, it must be done with database access:

```sql
-- Confirm you have the right account first
SELECT id, username, email, mfa_enabled FROM users WHERE username = 'theuser';

-- Remove the second factor and its recovery codes
DELETE FROM recovery_codes  WHERE user_id = <id>;
DELETE FROM mfa_credentials WHERE user_id = <id>;
UPDATE users SET mfa_enabled = 0 WHERE id = <id>;

-- Revoke any live sessions
DELETE FROM server_sessions WHERE user_id = <id>;
```

### Afterwards

1. **Record what you did, when, and how you verified the identity.** Note that
   this manual step does not write to the audit log, so your written record is
   the only evidence.
2. Tell the user to sign in and immediately enrol again.
3. Confirm they have saved the new recovery codes.
4. Watch that account's events for the next few days.

---

## 8. Routine checks

### Daily
- [ ] Failed sign-ins in the last 24 hours — any unusual spike?
- [ ] Any currently locked accounts?
- [ ] Any `mfa_verify_replay_rejected` events?

### Weekly
- [ ] MFA adoption percentage — is it rising?
- [ ] Any recovery-code use that was not reported to you?
- [ ] Any accounts with repeated failures across several days?
- [ ] Confirm database backups are running

### Monthly
- [ ] Review all administrator accounts — are they all still needed, and do they
      all have MFA enabled?
- [ ] Review deactivated accounts — can any be removed?
- [ ] Check for dependency updates with security fixes
- [ ] Verify a backup actually restores
- [ ] Confirm `MFA_ENCRYPTION_KEY` is still backed up separately from the database

---

## 9. Encouraging MFA adoption

The MFA adoption figure is the number that matters most on the dashboard. A
system where only a quarter of accounts have a second factor is a system where
three quarters are one leaked password away from compromise.

What helps, in rough order of effectiveness:

1. **Lead by example** — every administrator account enrolled first.
2. **Explain the threat in concrete terms.** "If a site you used was breached
   and you reused that password, someone can sign in as you right now" lands
   better than "security policy requires it".
3. **Make enrollment easy** — the system already shows both a QR code and a
   typed key, and proves the code works before switching anything on.
4. **Address the real fear**, which is being locked out. Point at the recovery
   codes, and make sure people actually save them.
5. **Consider making it mandatory for privileged accounts first**, then more
   broadly.

---

## 10. Command reference

```bash
flask --app wsgi create-admin --username NAME --email EMAIL   # create an administrator
flask --app wsgi seed-roles                                   # ensure roles exist
flask --app wsgi seed-demo                                    # demo accounts (dev only)
flask --app wsgi generate-keys                                # fresh SECRET_KEY / encryption key
flask --app wsgi show-config                                  # effective settings, secrets masked
flask --app wsgi db upgrade                                   # apply migrations
flask --app wsgi db current                                   # which migration is applied
pytest -q                                                     # run the test suite
```

### Useful queries for investigation

```sql
-- Accounts without a second factor
SELECT username, email, last_login_at FROM users
WHERE mfa_enabled = 0 AND is_active = 1;

-- Currently locked accounts
SELECT username, locked_until, failed_login_count FROM users
WHERE locked_until > NOW();

-- Failed sign-ins in the last hour, busiest first
SELECT username_attempted, ip_address, COUNT(*) AS failures
FROM audit_events
WHERE event_type = 'login_failed' AND created_at > NOW() - INTERVAL 1 HOUR
GROUP BY username_attempted, ip_address
ORDER BY failures DESC;

-- Everything that happened to one account
SELECT created_at, event_type, outcome, ip_address, detail
FROM audit_events
WHERE user_id = (SELECT id FROM users WHERE username = 'theuser')
ORDER BY created_at DESC;

-- Replayed codes blocked, by user
SELECT u.username, COUNT(*) AS blocked
FROM audit_events a JOIN users u ON u.id = a.user_id
WHERE a.event_type = 'mfa_verify_replay_rejected'
GROUP BY u.username ORDER BY blocked DESC;
```
