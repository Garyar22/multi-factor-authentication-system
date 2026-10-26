# Database Design

**Project:** Multi-Factor Authentication (MFA) System for Securing Web Applications
**Student:** Yahye Ahmed Adan · ISBAT University, Kampala
**Phase 2 deliverable** · 23 October 2026

The schema reproduced here was **exported from the live database** after
`flask db upgrade`, not written by hand. The raw export is in
[`diagrams/schema_mysql.sql`](diagrams/schema_mysql.sql).

**Verified on:** MariaDB 10.11.14 · InnoDB · `utf8mb4` / `utf8mb4_unicode_ci`

---

## 1. Entity-relationship diagram

```
                          ┌───────────────────────────┐
                          │          roles            │
                          ├───────────────────────────┤
                          │ PK id          INT        │
                          │ UQ name        VARCHAR(32)│
                          │    description VARCHAR(255)│
                          │    created_at  DATETIME   │
                          └─────────────┬─────────────┘
                                        │ 1
                                        │
                                        │ assigned to
                                        │
                                        │ N
                          ┌─────────────▼─────────────┐
                          │           users           │
                          ├───────────────────────────┤
                          │ PK id                 INT │
                          │ UQ username   VARCHAR(64) │
                          │ UQ email      VARCHAR(255)│
                          │    password_hash  VC(255) │ ← Argon2id only
                          │    full_name      VC(120) │
                          │ FK role_id            INT │
                          │    is_active      BOOLEAN │
                          │    mfa_enabled    BOOLEAN │
                          │    failed_login_count INT │
                          │    locked_until  DATETIME │
                          │    last_login_at DATETIME │
                          │    password_changed_at DT │
                          │    created_at    DATETIME │
                          │    updated_at    DATETIME │
                          └──┬────┬────┬────┬────┬────┘
            1:1 ┌────────────┘    │    │    │    └──────────────┐ 1:N
                │           1:N ┌─┘    │    └─┐ 1:N             │
                ▼               ▼      │      ▼                 ▼
 ┌──────────────────────┐ ┌───────────┐│ ┌──────────────┐ ┌──────────────────┐
 │   mfa_credentials    │ │recovery_  ││ │password_     │ │ audit_events     │
 ├──────────────────────┤ │codes      ││ │reset_tokens  │ ├──────────────────┤
 │ PK id            INT │ ├───────────┤│ ├──────────────┤ │ PK id        INT │
 │ UQ,FK user_id    INT │ │ PK id INT ││ │ PK id    INT │ │    event_type VC │
 │ secret_encrypted TEXT│ │ FK user_id││ │ FK user_id   │ │    category   VC │
 │        ↑ Fernet      │ │ code_hash ││ │ UQ token_hash│ │    outcome    VC │
 │ method       VC(16)  │ │   ↑Argon2 ││ │   ↑ SHA-256  │ │ FK user_id (null)│
 │ confirmed_at     DT  │ │ used_at DT││ │ expires_at DT│ │ username_attempted│
 │ last_used_counter INT│ │ created_at││ │ used_at   DT │ │ ip_address    VC │
 │        ↑ replay guard│ └───────────┘│ │ created_at DT│ │ user_agent    VC │
 │ created_at / updated │              │ └──────────────┘ │ detail       VC  │
 └──────────────────────┘              │                  │ created_at    DT │
                                       │ 1:N              └──────────────────┘
                     ┌─────────────────┴──────┐  1:N
                     ▼                        ▼
      ┌────────────────────────┐  ┌──────────────────────────┐
      │pending_authentications │  │    server_sessions       │
      ├────────────────────────┤  ├──────────────────────────┤
      │ PK id              INT │  │ PK sid       VARCHAR(64) │
      │ UQ token   VARCHAR(64) │  │ FK user_id (nullable) INT│
      │ FK user_id         INT │  │    data             TEXT │
      │    expires_at       DT │  │    expires_at   DATETIME │
      │    attempts        INT │  │    created_at   DATETIME │
      │    consumed_at      DT │  │    updated_at   DATETIME │
      │    ip_address  VC(45)  │  │    ip_address    VC(45)  │
      │    created_at       DT │  │    user_agent    VC(255) │
      └────────────────────────┘  └──────────────────────────┘
         the half-authenticated       the authenticated state
         state lives here                 lives here
```

### Relationship summary

| From | To | Cardinality | Delete behaviour | Why |
|------|----|-------------|------------------|-----|
| `roles` → `users` | 1 : N | One role, many users | Restrict | A role in use must not vanish |
| `users` → `mfa_credentials` | 1 : 1 | At most one TOTP credential | Cascade | The credential is meaningless without the user |
| `users` → `recovery_codes` | 1 : N | Ten per enrollment | Cascade | Same |
| `users` → `password_reset_tokens` | 1 : N | Several over time | Cascade | Same |
| `users` → `pending_authentications` | 1 : N | One live at a time | Cascade | Same |
| `users` → `server_sessions` | 1 : N | One per signed-in device | Cascade | Same |
| `users` → `audit_events` | 1 : N | Many | **No cascade**, `user_id` nullable | **Deliberate.** Audit history must survive the deletion of the account it describes, and failed logins against usernames that never existed must still be recorded |

---

## 2. Tables in detail

### 2.1 `roles`

Underpins role-based access control. Two rows are seeded by
`flask seed-roles`.

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `id` | INT | PK, auto-increment | Surrogate key |
| `name` | VARCHAR(32) | **UNIQUE**, NOT NULL, indexed | `admin` or `user` |
| `description` | VARCHAR(255) | NULL | Human-readable explanation |
| `created_at` | DATETIME | NOT NULL | Audit trail |

**Design note.** Roles are a table rather than a string column on `users`, so
adding a third role (an auditor who can read the log but not change accounts,
say) needs no schema migration.

---

### 2.2 `users`

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `id` | INT | PK | Surrogate key |
| `username` | VARCHAR(64) | **UNIQUE**, NOT NULL, indexed | Login identifier |
| `email` | VARCHAR(255) | **UNIQUE**, NOT NULL, indexed | Alternative login and reset address |
| `password_hash` | VARCHAR(255) | NOT NULL | **Argon2id PHC string; salt embedded. Never plaintext.** |
| `full_name` | VARCHAR(120) | NULL | Display name; optional by design (data minimisation) |
| `role_id` | INT | **FK → roles.id**, NOT NULL | Authorisation |
| `is_active` | BOOLEAN | NOT NULL, default true | Administrative deactivation |
| `mfa_enabled` | BOOLEAN | NOT NULL, default false | Whether the second factor is required |
| `failed_login_count` | INT | NOT NULL, default 0 | Lockout counter |
| `locked_until` | DATETIME | NULL | Lockout expiry; NULL means not locked |
| `last_login_at` | DATETIME | NULL | Shown to the user, so they can spot a login they did not make |
| `password_changed_at` | DATETIME | NULL | Password age |
| `created_at` / `updated_at` | DATETIME | NOT NULL | Record lifecycle |

**Indexes:** `ix_users_username` (unique), `ix_users_email` (unique),
`ix_users_role_id`, `ix_users_role_active` (composite on `role_id, is_active`).

**Why 255 for the hash.** An Argon2id PHC string at these parameters is about
100 characters; 255 leaves room for stronger parameters later without a
migration.

**Why lockout state lives on the user row** rather than in the rate limiter: an
in-memory limiter resets when the process restarts, which would hand an
attacker a free reset. A database column survives restarts.

---

### 2.3 `mfa_credentials`

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `id` | INT | PK | Surrogate key |
| `user_id` | INT | **FK → users.id, UNIQUE**, NOT NULL | Enforces one credential per user at the schema level |
| `secret_encrypted` | TEXT | NOT NULL | **Fernet ciphertext of the base32 TOTP secret.** The key is in the environment, never here |
| `method` | VARCHAR(16) | NOT NULL, default `totp` | Leaves room for a future `webauthn` value |
| `confirmed_at` | DATETIME | NULL | **NULL means enrollment was started but never proved.** MFA is not enforced until this is set |
| `last_used_counter` | INT | NULL | **Replay prevention.** The RFC 6238 time step of the last accepted code |
| `created_at` / `updated_at` | DATETIME | NOT NULL | Lifecycle |

**`last_used_counter` is the replay control.** When a code matches at step *c*,
the server stores *c*. A later code is accepted only if its step is strictly
greater. Without this column, any code stays usable for the whole ±1-step
window — roughly ninety seconds — and a shoulder-surfed code would work twice.

**The UNIQUE constraint on `user_id` is doing real work.** Without it, a bug
could create a second credential row and leave the system unsure which secret
is authoritative.

---

### 2.4 `recovery_codes`

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `id` | INT | PK | Surrogate key |
| `user_id` | INT | FK → users.id, NOT NULL, indexed | Owner |
| `code_hash` | VARCHAR(255) | NOT NULL | **Argon2id hash. The plaintext exists only in the browser, once** |
| `used_at` | DATETIME | NULL | NULL means unused; set once, and never cleared |
| `created_at` | DATETIME | NOT NULL | Issue time |

**Index:** `ix_recovery_user_used` on `(user_id, used_at)` — the lookup the
verification path performs.

**Rows are marked, not deleted.** Keeping a used code's row preserves the
evidence that it was used, which matters during an incident investigation.

---

### 2.5 `password_reset_tokens`

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `id` | INT | PK | Surrogate key |
| `user_id` | INT | FK → users.id, NOT NULL, indexed | Owner |
| `token_hash` | VARCHAR(64) | **UNIQUE**, NOT NULL, indexed | **SHA-256 hex digest of the token** |
| `expires_at` | DATETIME | NOT NULL | Short window (30 minutes by default) |
| `used_at` | DATETIME | NULL | Enforces single use |
| `created_at` | DATETIME | NOT NULL | Issue time |

**Why plain SHA-256 is correct here**, where Argon2id is used for passwords: the
input is a 256-bit cryptographically random value, not a low-entropy human
secret. There is no dictionary to search, so key stretching adds cost without
adding security. Storing only the digest means a database dump does not yield
working reset links.

---

### 2.6 `pending_authentications`

The half-authenticated state — the table that makes the MFA bypass impossible.

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `id` | INT | PK | Surrogate key |
| `token` | VARCHAR(64) | **UNIQUE**, NOT NULL, indexed | 256-bit random value; the cookie holds only this |
| `user_id` | INT | FK → users.id, NOT NULL, indexed | Who is half-authenticated |
| `expires_at` | DATETIME | NOT NULL | Five minutes by default |
| `attempts` | INT | NOT NULL, default 0 | Caps second-factor guesses against one state |
| `consumed_at` | DATETIME | NULL | Set when used, expired or abandoned |
| `ip_address` | VARCHAR(45) | NULL | IPv6-capable; for the audit trail |
| `created_at` | DATETIME | NOT NULL | Issue time |

**Why this is a table rather than a session flag.** If the half-authenticated
state were a value in the session, its authoritative copy would be whatever the
client sends back. Here the cookie carries an opaque token and every property
that matters — which user, whether it has expired, how many attempts remain —
is read from the server's own row.

---

### 2.7 `server_sessions`

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `sid` | VARCHAR(64) | **PK** | Opaque random session id; the only thing in the cookie |
| `user_id` | INT | FK → users.id, NULL, indexed | NULL for an anonymous session; set once authenticated |
| `data` | TEXT | NOT NULL | JSON session payload, held **server-side** |
| `expires_at` | DATETIME | NOT NULL, indexed | Absolute expiry; also drives the sweep |
| `created_at` / `updated_at` | DATETIME | NOT NULL | Lifecycle |
| `ip_address` | VARCHAR(45) | NULL | Where the session is being used from |
| `user_agent` | VARCHAR(255) | NULL | Which client |

**Why this table exists.** Flask's default session is a signed cookie: the whole
payload travels to the browser, the server keeps no record, and "logging out"
only asks the browser to forget it. That fails the specification's requirement
for server-side sessions and makes genuine revocation impossible. With this
table, `logout()` deletes the row and the cookie instantly becomes worthless —
and an administrator deactivating an account can sign that user out everywhere
at once (`invalidate_user_sessions`).

**Indexing `user_id`** is what makes that bulk revocation a single statement.

---

### 2.8 `audit_events`

| Column | Type | Constraints | Purpose |
|--------|------|-------------|---------|
| `id` | INT | PK | Sequence; gaps would indicate deletion |
| `event_type` | VARCHAR(64) | NOT NULL, indexed | e.g. `login_failed`, `mfa_verify_replay_rejected` |
| `category` | VARCHAR(32) | NOT NULL, indexed | `auth`, `mfa`, `account`, `admin`, `access` |
| `outcome` | VARCHAR(16) | NOT NULL, indexed | `success`, `failure`, `blocked` |
| `user_id` | INT | FK → users.id, **NULL allowed**, indexed | NULL when the username did not exist |
| `username_attempted` | VARCHAR(64) | NULL | **Preserves spray patterns against non-existent accounts** |
| `ip_address` | VARCHAR(45) | NULL | Source |
| `user_agent` | VARCHAR(255) | NULL | Client |
| `detail` | VARCHAR(255) | NULL | Free text, **passed through the secret scrubber** |
| `created_at` | DATETIME | NOT NULL, `DEFAULT CURRENT_TIMESTAMP`, indexed | When |

**Indexes:** on `event_type`, `category`, `outcome`, `user_id`, `created_at`,
plus a composite `ix_audit_type_created` on `(event_type, created_at)` — the
pattern the admin dashboard uses for "how many failed logins in the last 24
hours".

**What this table structurally cannot hold.** There is no column for a
password, an OTP value, a recovery code, a reset token or a session id.
`tests/test_models_and_admin.py` asserts this against the model's column names,
so a future change that added such a column would fail the suite.

**Append-only in practice.** The application issues only INSERT and SELECT
against this table. `DEPLOYMENT.md` §9 documents revoking UPDATE and DELETE
from the runtime MySQL account, so that even a compromised application cannot
rewrite its own history.

---

## 3. Normalisation

The schema is in **third normal form**.

| Form | Check |
|------|-------|
| **1NF** | Every column holds a single atomic value. No comma-separated lists; the ten recovery codes are ten rows, not one field |
| **2NF** | Every table has a single-column surrogate primary key, so no partial dependency on a composite key is possible |
| **3NF** | No transitive dependencies. Role *description* lives with the role, not copied onto every user. `is_admin` is derived at runtime from the joined role name rather than stored |

**One deliberate denormalisation:** `audit_events.username_attempted` duplicates
what `users.username` would give for a known user. This is intentional — the
column must hold usernames that have no row in `users` at all (failed logins
against accounts that do not exist), and it must keep its value if the account
is later deleted. Normalising it away would destroy exactly the evidence an
administrator needs.

---

## 4. Data protection summary

| Data | Stored as | Reversible? | If the database leaks |
|------|-----------|-------------|-----------------------|
| Password | Argon2id hash, per-user salt, 64 MiB cost | **No** | Offline cracking only; slow, and the policy blocks predictable choices |
| TOTP secret | Fernet ciphertext, key in the environment | Only with the key | **Useless without the key**, which is not in the database |
| Recovery code | Argon2id hash | **No** | Useless |
| Reset token | SHA-256 digest | **No** | Useless |
| Session id | Random, server-side row | n/a | Rows can be deleted to revoke every session |
| Pending token | Random, short-lived | n/a | Expires within minutes |
| Email, username, IP | Plaintext | n/a | Personal data; restricted to administrators |

---

## 5. Migration strategy

Schema changes go through **Alembic** via Flask-Migrate. No manual `ALTER TABLE`
is performed against a deployed database, so every environment can be rebuilt
from the same recorded history.

```bash
flask --app wsgi db init                      # once, already done
flask --app wsgi db migrate -m "description"  # generate from model changes
flask --app wsgi db upgrade                   # apply
flask --app wsgi db downgrade                 # revert one step
flask --app wsgi db current                   # which revision is applied
flask --app wsgi db history                   # full history
```

**Current state:** one revision, `a30857d12888`, creating all eight tables.
Applied successfully to MariaDB 10.11.14 on 23 October 2026.

**Practice followed:** auto-generated migrations are read before being applied.
Alembic's autogeneration is good at detecting added tables and columns, and
unreliable about renames and some type changes, so the generated script is
reviewed rather than trusted.

---

## 6. Sample data

`flask seed-demo` creates three non-privileged demonstration accounts with
**randomly generated passwords printed once to the terminal**. No credential is
written into the repository, and no account is created with a known password.
The command refuses to run without confirmation, so it cannot be executed
against a real database by accident.

Administrator accounts are **never** seeded. They are created explicitly with
`flask create-admin`, which prompts for a password and enforces the same policy
as user registration.
