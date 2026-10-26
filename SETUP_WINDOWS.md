# Running the system on Windows

A step-by-step walkthrough for getting the application running on a Windows
machine, written for the defence demonstration. The commands are PowerShell.
`docs/DEPLOYMENT.md` carries the full version, including Linux and production
deployment; this file is the short path.

Allow about 40 minutes the first time, most of it waiting for MySQL to install.

---

## 1. What you need first

| Thing | Where | Note |
|---|---|---|
| Python 3.11 or newer | python.org/downloads | On the first installer screen, tick **Add python.exe to PATH** |
| MySQL Community Server 8.0 | dev.mysql.com/downloads/mysql | Write the root password down; you need it in step 4 |
| An authenticator app | Google Authenticator, Microsoft Authenticator, Authy, FreeOTP or Aegis | Any RFC 6238 app works |

Check Python is visible before going on. Open PowerShell and run:

```powershell
python --version
```

If that prints an error rather than a version, Python is not on PATH. Reinstall
it and tick the box, or add it manually.

---

## 2. Extract the project

Right-click `MFA-System-Yahye-Ahmed-Adan.zip` in your Downloads folder and
choose **Extract All**. Then open PowerShell in the extracted folder: hold
Shift, right-click inside the folder, and choose **Open PowerShell window
here**.

Everything below runs from that folder, the one containing `wsgi.py`.

---

## 3. Create the virtual environment and install the dependencies

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

Your prompt should now start with `(venv)`. If PowerShell refuses to run
`activate` with a script-execution error, run this once and try again:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

---

## 4. Create the database

Open `scripts\create_database.sql` in Notepad and replace
`CHANGE_THIS_PASSWORD` with a password you choose for the application's
database account. Save it, then run:

```powershell
mysql -u root -p < scripts\create_database.sql
```

Enter your MySQL **root** password when prompted.

If PowerShell says `mysql` is not recognised, it is not on PATH. Either use the
full path:

```powershell
& "C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p < scripts\create_database.sql
```

or open **MySQL Workbench**, connect as root, and paste the contents of the
`.sql` file into a query tab and run it.

---

## 5. Create your configuration file

```powershell
copy .env.example .env
```

Open `.env` in Notepad. You need to set four values:

* `SECRET_KEY` and `MFA_ENCRYPTION_KEY` — generate them in the next step.
* `MYSQL_PASSWORD` — the password you chose in step 4.
* `MYSQL_USER` is already `mfa_user`, which is what the SQL script created.

Generate the two secrets:

```powershell
flask --app wsgi generate-keys
```

Copy each printed value into the matching line in `.env` and save the file.

> Keep `MFA_ENCRYPTION_KEY` safe. It decrypts the stored TOTP secrets. If it is
> lost, every enrolled user has to enrol again.

---

## 6. Build the schema and create your administrator

```powershell
flask --app wsgi db upgrade
flask --app wsgi seed-roles
flask --app wsgi create-admin --username sysadmin --email you@example.com
```

The last command prompts for a password and never echoes or stores it. There is
no default administrator password in this project.

The password must satisfy the same policy as every other account: at least 12
characters, upper and lower case, a digit, a symbol, and it must not be
predictable or contain your username. `Password123!` will be refused, which is
the behaviour demonstrated in the report.

---

## 7. Run it

```powershell
flask --app wsgi run
```

Open <http://127.0.0.1:5000> in a browser. Leave the PowerShell window open
while you demonstrate; closing it stops the server. Press Ctrl+C to stop.

---

## 8. Walk through it once before the defence

1. **Create an account** from the landing page. Try `Password123!` first so the
   panel sees the policy refuse it, then use a real passphrase.
2. **Sign in.** You reach the dashboard directly, because MFA is not yet on.
3. **Security settings → enable two-step verification.** Scan the QR code with
   your authenticator app, type the current code, and confirm.
4. **Save the ten recovery codes.** They are shown once, because only their
   hashes are stored.
5. **Sign out, then sign in again.** This time the password only reaches the
   verification page.
6. **The demonstration that matters:** while sitting on the verification page,
   type `http://127.0.0.1:5000/dashboard` into the address bar. The server
   refuses and sends you back. That is the central claim of the project, live.
7. **Use a recovery code**, then try the same code a second time and watch it
   be refused.
8. **Sign in as `sysadmin`** to show the administrator dashboard and the audit
   log.

---

## 9. Proving it works without clicking anything

```powershell
pytest
```

219 tests, no database server needed, about 20 seconds. This is worth running in
front of the panel: the suite performs the attacks and asserts that they fail.

For the coverage figure quoted in the report:

```powershell
pytest --cov=app --cov-report=term-missing
```

---

## 10. If something goes wrong

**`ModuleNotFoundError: No module named 'flask'`**
The virtual environment is not active. Run `venv\Scripts\activate` and look for
`(venv)` in the prompt.

**`Can't connect to MySQL server on 'localhost'`**
MySQL is not running. Open **Services**, find `MySQL80`, and start it.

**`Access denied for user 'mfa_user'@'localhost'`**
`MYSQL_PASSWORD` in `.env` does not match the password you put in
`create_database.sql`. Fix one to match the other.

**`Unknown database 'mfa_db'`**
Step 4 did not run. Run it again and check for errors.

**The authenticator codes are always rejected**
Almost always a clock problem; the phone and the computer must agree to within
about a minute. Run `w32tm /resync` in an Administrator PowerShell, and turn on
automatic date and time on the phone. In Google Authenticator there is also
*Settings → Time correction for codes → Sync now*.

**`429 Too Many Requests` while you are testing**
The rate limiter is doing its job. Wait a minute, or set
`RATELIMIT_ENABLED=false` in `.env` while you practise, and set it back to
`true` before you demonstrate.

**Locked out of an account after failed attempts**
Sign in as the administrator and clear the lockout from the user management
page, or wait for it to expire.

**Port 5000 already in use**
`flask --app wsgi run --port 5050`, then open
<http://127.0.0.1:5050>.

More cases, with the exact error text, are in `docs/DEPLOYMENT.md` section 12.

---

## 11. If MySQL will not install in time

The application can run on SQLite instead, with no database server at all. Put
this one line in `.env` in place of the `MYSQL_*` settings:

```
DATABASE_URL=sqlite:///C:/Users/YOUR_NAME/mfa_demo.db
```

Then run steps 6 and 7 as written. This was tested and works: the migration
builds the same eight tables and every page behaves identically.

Two things to keep in mind. The report documents MySQL as the database, so use
MySQL for the defence if you possibly can, and say plainly that you fell back to
SQLite if you did not. And the project's MySQL evidence — the schema export, the
migration output, the test run on MariaDB — was produced on MySQL, so a SQLite
demonstration shows the application working but not that particular evidence
being reproduced.
