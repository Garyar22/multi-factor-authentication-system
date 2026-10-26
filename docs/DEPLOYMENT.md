# Deployment and Troubleshooting Guide

**Project:** Multi-Factor Authentication (MFA) System for Securing Web Applications
**Student:** Yahye Ahmed Adan · ISBAT University, Kampala

Every command here was executed during development. The outputs quoted are the
ones the tools actually produced.

---

## 1. Prerequisites

| Requirement | Version | Check with |
|-------------|---------|-----------|
| Python | 3.11 or newer (developed on 3.13.17) | `python --version` |
| pip | any recent | `pip --version` |
| MySQL **or** MariaDB | MySQL 8.0+ / MariaDB 10.6+ | `mysql --version` |
| Git | optional | `git --version` |
| Authenticator app | any RFC 6238 app | on your phone |

**Works on Windows, Linux and macOS.** Where the command differs, both are
given. PyMySQL was chosen specifically because it is pure Python — no C
compiler or MySQL development headers are needed, which is the usual stumbling
block on Windows.

---

## 2. Install

### 2.1 Get the project

```bash
cd mfa-system
```

### 2.2 Create a virtual environment

A virtual environment keeps the pinned versions from colliding with anything
else on the machine.

```bash
python -m venv venv

source venv/bin/activate          # Linux / macOS
venv\Scripts\activate             # Windows (Command Prompt)
venv\Scripts\Activate.ps1         # Windows (PowerShell)
```

The prompt should now start with `(venv)`.

### 2.3 Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

On Windows, also install the production server for that platform:

```bash
pip install waitress==3.0.2
```

Verify:

```bash
python -c "import flask, pyotp, argon2, cryptography, pymysql; print('All core libraries import correctly')"
```

---

## 3. Create the MySQL database

### 3.1 Run the supplied script

**First edit `scripts/create_database.sql` and replace
`CHANGE_THIS_PASSWORD` with a password you choose.**

```bash
mysql -u root -p < scripts/create_database.sql
```

### 3.2 Or do it by hand

```sql
CREATE DATABASE mfa_db      CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE DATABASE mfa_test_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'mfa_user'@'localhost' IDENTIFIED BY 'your-password-here';

GRANT SELECT, INSERT, UPDATE, DELETE ON mfa_db.* TO 'mfa_user'@'localhost';
GRANT CREATE, ALTER, INDEX, REFERENCES, DROP ON mfa_db.* TO 'mfa_user'@'localhost';
GRANT ALL PRIVILEGES ON mfa_test_db.* TO 'mfa_user'@'localhost';

FLUSH PRIVILEGES;
```

**Why a dedicated account rather than root.** If the application is ever
compromised, the attacker inherits only these privileges — no access to other
databases, no `FILE` privilege, and no connections from any host but localhost.

**Why `utf8mb4`.** It stores the full Unicode range, including four-byte
characters. The older `utf8` alias in MySQL only handles three bytes and
silently truncates the rest.

Confirm:

```bash
mysql -u mfa_user -p -e "SHOW DATABASES LIKE 'mfa%';"
```

---

## 4. Configure

### 4.1 Create your `.env`

```bash
cp .env.example .env              # Linux / macOS
copy .env.example .env            # Windows
```

### 4.2 Generate the two required secrets

```bash
flask --app wsgi generate-keys
```

Output looks like this (**your values will differ — never reuse these**):

```
SECRET_KEY=3f8a...64 hex characters...
MFA_ENCRYPTION_KEY=dGhpc2lzYW5l...44 characters ending in =
```

Paste both into `.env`.

| Variable | What it does | If it is lost |
|----------|-------------|---------------|
| `SECRET_KEY` | Signs the session cookie | Everyone is signed out; no permanent harm |
| `MFA_ENCRYPTION_KEY` | Encrypts every TOTP secret at rest | **Every enrolled user must re-enrol.** Back it up separately from the database |

> **Back up `MFA_ENCRYPTION_KEY` somewhere other than the database backup.**
> Storing both together would defeat the purpose: the whole point is that a
> stolen database dump is not enough to decrypt the TOTP secrets.

### 4.3 Set the database credentials

```ini
MYSQL_USER=mfa_user
MYSQL_PASSWORD=your-password-here
MYSQL_HOST=localhost
MYSQL_PORT=3306
MYSQL_DB=mfa_db
```

### 4.4 Check what the application actually loaded

```bash
flask --app wsgi show-config
```

Real output from the development environment (the database password is masked
by the command itself):

```
Environment                 development
Database                    mysql+pymysql://mfa_user:****@127.0.0.1:3306/mfa_db?charset=utf8mb4
SECRET_KEY set              yes
MFA_ENCRYPTION_KEY set      yes
Session cookie secure       False
Session cookie httponly     True
Session cookie samesite     Lax
Session idle timeout (min)  15
CSRF enabled                True
Rate limiting enabled       True
Argon2 time cost            3
Argon2 memory cost (KiB)    65536
Argon2 parallelism          2
TOTP digits                 6
TOTP interval (s)           30
TOTP skew window (steps)    1
Max failed logins           5
Lockout (min)               15
Password min length         12
Recovery code count         10
Pending MFA TTL (s)         300
```

---

## 5. Create the schema

```bash
flask --app wsgi db upgrade
```

Real output:

```
INFO  [alembic.runtime.migration] Context impl MySQLImpl.
INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> a30857d12888, Initial schema: ...
```

Confirm all eight tables exist:

```bash
mysql -u mfa_user -p mfa_db -e "SHOW TABLES;"
```

```
alembic_version
audit_events
mfa_credentials
password_reset_tokens
pending_authentications
recovery_codes
roles
server_sessions
users
```

---

## 6. Seed roles and create an administrator

```bash
flask --app wsgi seed-roles
```

```
Roles ready. 2 created.
```

```bash
flask --app wsgi create-admin --username sysadmin --email admin@yourdomain.example
```

You are prompted for a password, twice, and it is never echoed. It must satisfy
the same policy as every user account.

```
Administrator 'sysadmin' created.
Sign in and enable two-step verification on this account immediately.
```

> **There is no default administrator password anywhere in this project**, and
> no hidden bypass account. If you want to avoid typing the password at an
> interactive prompt, set `ADMIN_PASSWORD` in the environment for that one
> command and remove it afterwards.

Optional, for a demonstration database only:

```bash
flask --app wsgi seed-demo
```

This creates three non-privileged accounts with **randomly generated passwords
printed once**. Nothing is stored in the repository.

---

## 7. Run it

### 7.1 Development

```bash
flask --app wsgi run
```

Open <http://127.0.0.1:5000>.

To reach it from another device on the same network (useful when scanning the
QR code with a phone):

```bash
flask --app wsgi run --host 0.0.0.0 --port 5000
```

Then browse to `http://<your-machine-ip>:5000`. Your firewall may need to allow
the port.

> The Flask development server is single-threaded and not built for production.
> Use §7.2 or §7.3 for anything beyond development.

### 7.2 Production on Linux — Gunicorn

```bash
# In .env
FLASK_CONFIG=production
SESSION_COOKIE_SECURE=true
TRUST_PROXY_HEADERS=true
```

```bash
gunicorn --workers 3 --bind 127.0.0.1:8000 \
         --access-logfile logs/access.log \
         --error-logfile logs/error.log \
         wsgi:app
```

**Worker count:** `(2 × CPU cores) + 1` is the usual starting point. Note that
Argon2 at 64 MiB means each concurrent hash holds 64 MiB, so budget memory for
workers × concurrent logins.

**In production the application refuses to start without `SECRET_KEY` and
`MFA_ENCRYPTION_KEY`.** That is deliberate: silently generating a temporary key
would mean every enrolled user's TOTP secret became undecryptable at the next
restart.

### 7.3 Production on Windows — Waitress

Gunicorn does not run on Windows.

```bash
pip install waitress==3.0.2
waitress-serve --listen=127.0.0.1:8000 wsgi:app
```

### 7.4 Behind nginx with HTTPS

```nginx
server {
    listen 443 ssl http2;
    server_name mfa.example.ac.ug;

    ssl_certificate     /etc/letsencrypt/live/mfa.example.ac.ug/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mfa.example.ac.ug/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /path/to/mfa-system/app/static/;
        expires 30d;
    }
}

server {
    listen 80;
    server_name mfa.example.ac.ug;
    return 301 https://$host$request_uri;
}
```

Set `TRUST_PROXY_HEADERS=true` so the application reads the real client IP from
`X-Forwarded-For` rather than recording every request as coming from the proxy.
Only enable this behind a proxy you control — otherwise a client could forge
the header and defeat per-IP rate limiting.

### 7.5 systemd service

```ini
[Unit]
Description=MFA System
After=network.target mysql.service

[Service]
User=mfaapp
WorkingDirectory=/opt/mfa-system
Environment="PATH=/opt/mfa-system/venv/bin"
EnvironmentFile=/opt/mfa-system/.env
ExecStart=/opt/mfa-system/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:8000 wsgi:app
Restart=always

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/mfa-system/logs

[Install]
WantedBy=multi-user.target
```

```bash
sudo chmod 600 /opt/mfa-system/.env
sudo chown mfaapp:mfaapp /opt/mfa-system/.env
sudo systemctl enable --now mfa-system
```

---

## 8. HTTPS is required in production

`SESSION_COOKIE_SECURE=true` tells the browser to send the session cookie only
over HTTPS. Over plain HTTP the cookie is sent in clear text and anyone on the
network path can copy it and impersonate the user — which would undo the MFA
entirely.

**Note the trap:** if you set `SESSION_COOKIE_SECURE=true` and then serve over
plain HTTP, the browser will not send the cookie at all and logins will appear
to succeed and then immediately fail. That is the setting working as designed,
not a bug.

For local development, use Let's Encrypt in production or a self-signed
certificate locally:

```bash
pip install cryptography
flask --app wsgi run --cert=adhoc
```

---

## 9. Hardening the audit log

The application only ever INSERTs into and SELECTs from `audit_events`. After
the first `flask db upgrade`, you can withhold UPDATE and DELETE from the
runtime account so that even a fully compromised application cannot rewrite its
own security history:

```sql
REVOKE UPDATE, DELETE ON mfa_db.audit_events FROM 'mfa_user'@'localhost';
FLUSH PRIVILEGES;
```

**Trade-off, stated honestly:** a future migration that needed to alter rows in
that table would then fail until the privilege was granted back. And this is
append-only *within the database* — an attacker with MySQL administrative
access could still change it. Genuine tamper-evidence requires shipping logs to
a separate host, which is outside the scope of this project.

---

## 10. Verifying the deployment

```bash
# 1. The application responds
curl -I http://127.0.0.1:8000/

# 2. The database connection is healthy
curl http://127.0.0.1:8000/healthz
# {"status": "ok"}

# 3. Security headers are present
curl -sI http://127.0.0.1:8000/ | grep -iE "content-security|x-frame|x-content|referrer"

# 4. Protected pages are not reachable anonymously
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/dashboard
# 302

# 5. The test suite passes
pytest -q
```

Then, by hand: register an account, enable two-step verification, sign out,
sign back in, and confirm you are asked for a code.

---

## 11. Backup and recovery

| What | How | How often |
|------|-----|-----------|
| Database | `mysqldump -u root -p mfa_db > backup-$(date +%F).sql` | Daily |
| **`MFA_ENCRYPTION_KEY`** | **Store securely and separately from the database backup** | Once, and whenever it changes |
| `SECRET_KEY` | With the configuration | Once |
| Application code | Version control | Continuously |

**Restoring:**

```bash
mysql -u root -p mfa_db < backup-2026-10-23.sql
```

Restore the `.env` with the **same** `MFA_ENCRYPTION_KEY`. With a different
key, every stored TOTP secret becomes undecryptable and every enrolled user has
to enrol again. The application fails closed in that case — it denies access
rather than letting anyone in — which is the correct behaviour, but it is a
painful morning, so keep the key safe.

---

## 12. Troubleshooting

### `ModuleNotFoundError: No module named 'flask'`
The virtual environment is not active. Re-run the activate command from §2.2;
your prompt should show `(venv)`.

### `Can't connect to MySQL server on 'localhost'`
MySQL is not running.
```bash
sudo systemctl start mysql       # Linux
net start MySQL80                # Windows (as Administrator)
```

### `Access denied for user 'mfa_user'@'localhost'`
The password in `.env` does not match the one the account was created with.
Either correct `.env`, or reset the account password:
```sql
ALTER USER 'mfa_user'@'localhost' IDENTIFIED BY 'new-password';
FLUSH PRIVILEGES;
```

### `Unknown database 'mfa_db'`
Step 3 was skipped. Run `scripts/create_database.sql`.

### `Target database is not up to date`
```bash
flask --app wsgi db upgrade
```

### `MFA_ENCRYPTION_KEY is not a valid 32-byte url-safe base64 Fernet key`
The value in `.env` was truncated or altered. Generate a fresh one with
`flask --app wsgi generate-keys`. **Be aware:** a new key means existing
enrolled users must re-enrol.

### Codes from the authenticator app are always rejected
Almost always a clock problem. The server and the phone must agree on the time
to within roughly a minute.

```bash
timedatectl                       # Linux: check NTP is synchronised
sudo timedatectl set-ntp true
w32tm /resync                     # Windows, as Administrator
```

On the phone, enable automatic date and time. In Google Authenticator there is
also *Settings → Time correction for codes → Sync now*.

If the clocks are fine, confirm the account in the app matches the issuer shown
during enrollment — it is easy to end up with two entries after a re-enrollment.

### "That code is not valid" immediately after signing in successfully
This is **expected behaviour**, not a fault. Replay protection burns the time
step of each accepted code, so the same code cannot be used twice. Wait for the
app to show the next code.

### Logged out immediately after logging in
`SESSION_COOKIE_SECURE=true` while serving over plain HTTP. Either serve over
HTTPS or set it to `false` for local development.

### `429 Too Many Requests` during testing
Rate limiting is doing its job. Wait a minute, or raise the limits in `.env`
for a demonstration:
```ini
RATELIMIT_LOGIN=100 per minute
```

### Account locked out
Wait for `LOCKOUT_MINUTES`, or clear it as an administrator from
`/admin/users`, or directly:
```sql
UPDATE users SET locked_until = NULL, failed_login_count = 0 WHERE username = 'name';
```

### Rate limits behave inconsistently with several workers
Expected. The default `memory://` store is per-process, so each Gunicorn worker
counts separately. Use a shared store:
```ini
RATELIMIT_STORAGE_URI=redis://localhost:6379/0
```

### The QR code does not render
The `pillow` package is missing — `qrcode` needs it for PNG output.
```bash
pip install pillow==12.3.0
```

### `pytest` reports `no such table: users`
A test is running outside the `app` fixture, which creates the schema. Use the
provided fixtures.

### Port already in use
```bash
flask --app wsgi run --port 5001
lsof -i :5000                      # Linux/macOS: find what is holding it
netstat -ano | findstr :5000       # Windows
```

---

## 13. Operational checklist before a live deployment

- [ ] `FLASK_CONFIG=production`
- [ ] `SECRET_KEY` and `MFA_ENCRYPTION_KEY` set to freshly generated values
- [ ] `MFA_ENCRYPTION_KEY` backed up separately from the database
- [ ] `SESSION_COOKIE_SECURE=true` **and** HTTPS actually configured
- [ ] `.env` permissions restricted (`chmod 600`) and not in version control
- [ ] MySQL account is not `root` and is limited to localhost
- [ ] `flask db upgrade` applied
- [ ] Administrator account created with a strong password, and MFA enabled on it
- [ ] `TRUST_PROXY_HEADERS=true` only if actually behind a trusted proxy
- [ ] Shared rate-limit store configured if running more than one worker
- [ ] UPDATE/DELETE revoked on `audit_events` (§9) if the trade-off is acceptable
- [ ] Database backups scheduled and a restore tested
- [ ] `pytest` passes against the deployed configuration
- [ ] `/healthz` monitored
