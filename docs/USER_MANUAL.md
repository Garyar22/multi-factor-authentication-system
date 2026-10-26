# User Manual

**Multi-Factor Authentication System**
ISBAT University · Yahye Ahmed Adan

A guide for people using the system. Screenshots referred to here are in
[`screenshots/`](screenshots/) and listed in
[`screenshots/INDEX.md`](screenshots/INDEX.md).

---

## 1. What two-step verification does for you

Normally one thing protects your account: your password. If somebody learns it
— because a different website you used was breached, because you reused it, or
because you were tricked into typing it somewhere — they can sign in as you.

Two-step verification adds a second check. After your password, the system asks
for a six-digit code from an app on your phone. The code changes every thirty
seconds and never leaves your device. Someone who steals your password still
cannot get in, because they do not have your phone.

**It takes about two minutes to set up, once.**

### What it does not protect against

Being straightforward about this: if you are tricked into typing *both* your
password *and* a current code into a fake website, an attacker who is relaying
them to the real site in real time can get in. So still check that the web
address is the one you expect before typing anything. No code can protect you
from handing it to the wrong person.

---

## 2. Creating your account

**Screenshots 02–04**

1. Open the site and choose **Create account**.
2. Fill in:
   * **Username** — 3 to 64 characters: letters, digits, dot, dash or underscore
   * **Email address** — you will need access to this if you forget your password
   * **Full name** — optional
   * **Password** — see below
3. Tick the acknowledgement and choose **Create account**.

### Choosing a password

The bar fills in as you type and the checklist ticks off as each rule is met:

* at least 12 characters
* one uppercase letter
* one lowercase letter
* one digit
* one special character

Three further rules are applied when you submit:

* **It must not be predictable.** `Password123!` meets every rule above and is
  still rejected, because it is one of the most commonly used passwords in the
  world. So are `Welcome2024!`, `Qwerty12345!` and similar patterns. Capitalising
  the first letter and adding a year and an exclamation mark is exactly what
  attackers try first.
* **It must not contain your username or the first part of your email.**
* **It must not repeat the same character four or more times.**

**A good approach:** think of three or four unrelated words you will remember,
and join them with a digit and a symbol — `Harbour#Kismayo48!` is long, easy to
recall and hard to guess.

**Please do not reuse a password from another site here.** This is a university
demonstration system.

---

## 3. Signing in

**Screenshots 06–08**

1. Choose **Sign in**.
2. Enter your **username or email address** — either works.
3. Enter your password.
4. If you have two-step verification turned on, you will now be asked for a code
   (section 5). If not, you go straight to your dashboard.

### If it says "Invalid credentials"

The message is the same whether the username does not exist or the password is
wrong. That is deliberate: it stops anyone using the login page to discover
which accounts exist. Check your spelling, check Caps Lock, and use the **Show**
button to see what you have typed.

### If it says your account is locked

After five failed attempts the account locks for fifteen minutes. Wait, or ask
an administrator to clear it. During the lockout even the correct password is
refused — that is what makes the lockout useful.

---

## 4. Turning on two-step verification

**Screenshots 09–13**

### Step 1 — get an authenticator app

Any of these work, and all are free:

| App | Platform |
|-----|----------|
| Google Authenticator | Android, iOS |
| Microsoft Authenticator | Android, iOS |
| Authy | Android, iOS, desktop |
| FreeOTP | Android, iOS |
| Aegis Authenticator | Android |

### Step 2 — start enrollment

Sign in, then go to **Security** in the menu and choose **Set up two-step
verification**.

### Step 3 — add the account to your app

**Screenshot 10.** You will see a QR code.

* In your authenticator app, choose to add an account and **scan the QR code**.
* If you cannot scan it — a desktop app, or a camera that will not focus — use
  **Cannot scan? Enter this key by hand**. Type the key shown, and set the type
  to time-based with 6 digits and a 30-second interval. The **Copy key** button
  saves you some typing.

Your app now shows a six-digit code for this account, changing every 30 seconds.

### Step 4 — prove it works

Type the code your app is showing into **Step 2 — Confirm it works** and choose
**Enable two-step verification**.

**This step is required on purpose.** Nothing is switched on until you have
proved a code works, so a mis-scan cannot lock you out of your own account.

If the code is refused, see section 8.

### Step 5 — save your recovery codes

**Screenshot 12. This is the step people skip and later regret.**

You are shown **ten recovery codes**, like `K7M2P-9XQ4T`. Each works once, in
place of your phone.

**They are shown only once.** The system stores a scrambled version it cannot
reverse, so this page can never show them to you again.

Choose one of:

* **Download as a text file** — then move it somewhere safe
* **Print this page** — and keep the paper somewhere secure
* Write them down carefully

Then choose **I have saved these**.

**Where to keep them:** a password manager, a locked drawer, or with important
documents at home. **Not** as a photo in your phone's gallery — if you lose the
phone you lose both factors at once.

---

## 5. Signing in with two-step verification

**Screenshots 15, 18**

1. Enter your username and password as usual.
2. You are taken to the verification page.
3. Open your authenticator app and read the current code for this account.
4. Type the six digits and choose **Verify**.

You are signed in.

### Useful to know

* Codes change every 30 seconds. If one is about to expire, wait for the next.
* A code that has **just been used cannot be used again**, even within the same
  30 seconds. If you sign in, sign out and straight back in, wait for a fresh
  code. This stops anyone who glimpsed your screen from reusing what they saw.
* Spaces are fine — `123 456` is accepted.
* The verification step expires after a few minutes. If it does, sign in again.
* After five wrong codes you are returned to the start.

---

## 6. If you do not have your phone

**Screenshots 20–21**

1. On the verification page, choose **Use a recovery code**.
2. Enter one of the ten codes you saved.
3. You are signed in.

Upper or lower case is fine, and the dash is optional.

**Each code works once.** After using one, the system tells you how many remain.

**Afterwards you should:**

* Go to **Security** and choose **Generate new recovery codes** if you are
  running low.
* If you have a new phone, remove the old entry in your authenticator app, turn
  two-step verification off and set it up again on the new device.

### If you have lost your phone *and* your recovery codes

There is no self-service way out, on purpose — a self-service bypass would be
exactly the hole an attacker would use. Contact your administrator, who will
verify your identity before helping. Expect this to take some time; that delay
is a security feature.

---

## 7. Managing your account

### Change your password

**Security settings → Change password.** You need your current password. Your
session is reissued afterwards, so any other copy of it stops working.

### Generate new recovery codes

**Security → Generate new recovery codes.** Confirm with your password. **The
old codes stop working immediately**, so save the new set before leaving the page.

### Turn off two-step verification

**Security → Disable two-step verification.** You need your password *and* a
current code. Requiring both means that someone who hijacked your session alone
cannot strip your second factor.

Your recovery codes are deleted too. Think carefully: afterwards your account is
protected by your password alone.

### Reset a forgotten password

**Screenshots 23–25**

1. On the sign-in page choose **Forgot password?**
2. Enter your email address.
3. Follow the reset link and set a new password.

The reply is the same whether or not the address is registered, so the page
cannot be used to find out who has an account here.

> **In this demonstration system the reset link is shown on screen** because no
> mail server is configured. A real deployment would email it, and only to the
> account's own inbox. The page says so when it happens.

**Resetting your password does not switch off two-step verification.** If you
had it on, you will still be asked for a code. This matters: if a reset
disabled MFA, anyone who got into your email would have a complete bypass.

---

## 8. When something goes wrong

### "That code is not valid" every time

Almost always the clock on your phone.

* **Android, Google Authenticator:** Settings → Time correction for codes → Sync now
* **iPhone:** Settings → General → Date & Time → turn on **Set Automatically**
* **Any device:** make sure automatic date and time is on

Also check you are reading the code for the right account — it is easy to end up
with two similar entries after setting up twice.

### A code worked a moment ago and now does not

Expected. Each code can be used only once. Wait for the next one.

### "Your verification session expired"

You took too long between the password and the code. Sign in again.

### Locked out after too many attempts

Wait fifteen minutes, or contact an administrator.

### Signed out unexpectedly

Sessions end after 15 minutes of inactivity. Sign in again.

### Lost or replaced your phone

Use a recovery code to sign in, then turn two-step verification off and set it
up again on the new phone. Remember to save the new recovery codes.

---

## 9. Keeping your account safe

1. **Use a unique password here.** The main threat is a password reused from a
   site that has been breached.
2. **Turn on two-step verification.** It is the single biggest improvement you
   can make.
3. **Save your recovery codes somewhere you will find them** — and not only on
   the phone that holds your authenticator app.
4. **Check the web address before typing a code.** A code typed into a fake site
   can be relayed to the real one.
5. **Check "Last sign-in" on your dashboard.** If it shows a time you were not
   there, change your password and tell your administrator.
6. **Sign out on shared computers.** Signing out genuinely ends the session on
   the server, not just in the browser.
7. **Nobody legitimate will ever ask you for a code.** Not an administrator, not
   support, not by phone or email. Anyone who does is attacking you.

---

## 10. Quick reference

| I want to… | Where |
|------------|-------|
| Create an account | Home → Create account |
| Sign in | Home → Sign in |
| Turn on two-step verification | Security → Set up two-step verification |
| See my recovery codes | Only when generated — otherwise generate a new set |
| Generate new recovery codes | Security → Generate new recovery codes |
| Turn off two-step verification | Security → Disable two-step verification |
| Change my password | Security settings → Change password |
| Reset a forgotten password | Sign in → Forgot password? |
| Sign in without my phone | Verification page → Use a recovery code |
| See my recent activity | Dashboard → Your recent security activity |
| Sign out | **Sign out** in the top bar |
