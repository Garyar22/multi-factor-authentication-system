"""
Password hashing and password policy.

Argon2id is used through argon2-cffi. Argon2id is the hybrid variant
recommended by the Password Hashing Competition and by OWASP, because it
resists both GPU cracking (memory hardness) and side-channel attacks.

Parameters are read from configuration so that the report can quote exactly
what was used, and so that the cost can be lowered for the test suite without
touching application code.
"""

import re
import unicodedata

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError
from flask import current_app

# A small, project-local list. A production system would check a large
# breached-password corpus (for example Have I Been Pwned's k-anonymity API).
COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "123456", "12345678",
    "123456789", "1234567890", "qwerty", "qwerty123", "letmein", "welcome",
    "welcome123", "admin", "admin123", "administrator", "iloveyou", "monkey",
    "dragon", "football", "baseball", "sunshine", "princess", "abc123",
    "trustno1", "changeme", "default", "secret", "pass123", "test1234",
    "p@ssw0rd", "passsword", "isbat", "isbat123", "university", "mfa12345",
}


def _hasher() -> PasswordHasher:
    cfg = current_app.config
    return PasswordHasher(
        time_cost=cfg["ARGON2_TIME_COST"],
        memory_cost=cfg["ARGON2_MEMORY_COST"],
        parallelism=cfg["ARGON2_PARALLELISM"],
        hash_len=cfg["ARGON2_HASH_LEN"],
        salt_len=cfg["ARGON2_SALT_LEN"],
        type=Type.ID,  # Argon2id
    )


def dummy_hash() -> str:
    """
    A real Argon2id hash, used to equalise the time taken by a login attempt
    for a username that does not exist.

    The point is that verifying against it costs the *same* as verifying a
    genuine user's password. An earlier version of this code used a
    hand-written hash string, which argon2-cffi rejected as malformed in
    microseconds — so the "defence" actually created the very timing signal it
    was meant to remove: unknown usernames answered far faster than known ones,
    which is exactly how an attacker enumerates accounts.

    The value is computed once per process and cached on the application, so
    the cost is paid at first use rather than on every request.
    """
    cache = current_app.extensions.setdefault("mfa_dummy_hash", {})
    key = (
        current_app.config["ARGON2_TIME_COST"],
        current_app.config["ARGON2_MEMORY_COST"],
        current_app.config["ARGON2_PARALLELISM"],
    )
    if cache.get("key") != key:
        import secrets

        cache["key"] = key
        cache["value"] = _hasher().hash(secrets.token_urlsafe(32))
    return cache["value"]


def normalise(password: str) -> str:
    """NFKC-normalise so visually identical Unicode input hashes identically."""
    return unicodedata.normalize("NFKC", password)


def hash_password(password: str) -> str:
    """Return an Argon2id PHC-format hash string (salt is embedded)."""
    return _hasher().hash(normalise(password))


def verify_password(stored_hash: str, password: str) -> bool:
    """
    Constant-time-ish verification via argon2-cffi.

    Returns False on any mismatch or malformed hash rather than raising, so a
    corrupt row cannot turn into a 500 that leaks internals.
    """
    if not stored_hash or password is None:
        return False
    try:
        return _hasher().verify(stored_hash, normalise(password))
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """True when the hash was made with weaker parameters than current config."""
    try:
        return _hasher().check_needs_rehash(stored_hash)
    except (InvalidHashError, VerificationError):
        return False


# Common keyboard runs and digit sequences, checked as substrings.
SEQUENCES = (
    "qwerty", "qwertz", "azerty", "asdfgh", "zxcvbn", "qazwsx",
    "123456", "234567", "345678", "456789", "098765", "987654",
    "abcdef", "password", "passwort",
)

# Leetspeak substitutions are undone before the blocklist is consulted, so
# "P@ssw0rd!" is recognised as "password".
LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i",
                      "0": "o", "$": "s", "5": "s", "7": "t", "+": "t"})


def is_predictable(password: str) -> bool:
    """
    Catch the passwords that satisfy composition rules but are still guessed
    first in any real attack.

    Composition rules alone are close to useless here: "Password123!" has an
    uppercase letter, lowercase letters, a digit and a symbol, is twelve
    characters long, and is one of the most common passwords in existence.
    Attackers apply exactly these mangling rules, so the checker has to undo
    them before comparing against the blocklist:

    * lower-case the candidate;
    * undo common leetspeak substitutions;
    * strip trailing digits and punctuation (the "add a year and a bang"
      pattern) and leading digits;
    * then test the remaining core against the blocklist.

    It also rejects anything built mostly from a keyboard run such as
    "qwerty" or "123456".
    """
    if not password:
        return False

    lowered = password.lower()

    # Build the candidate forms. Decorations are stripped BEFORE leetspeak is
    # undone: doing it the other way round turns the trailing digits into
    # letters first, and the stripping step then has nothing to remove.
    trimmed = re.sub(r"[^a-z]+$", "", lowered)          # drop trailing digits/symbols
    trimmed = re.sub(r"^[^a-z]+", "", trimmed)          # drop leading digits/symbols
    letters_only = re.sub(r"[^a-z]", "", lowered)

    candidates = set()
    for form in (lowered, trimmed, letters_only):
        if form:
            candidates.add(form)
            candidates.add(form.translate(LEET))        # undo leetspeak

    if candidates & COMMON_PASSWORDS:
        return True

    # Reject anything that is essentially a keyboard run, with or without
    # decoration: "qwerty123!", "Qwerty12345!", "123456789a".
    for sequence in SEQUENCES:
        if trimmed == sequence or letters_only == sequence:
            return True
        if sequence in lowered and len(sequence) >= 0.6 * max(len(letters_only), 1):
            return True

    return False


def validate_password_strength(password: str, username: str = "", email: str = ""):
    """
    Server-side password policy. Returns a list of human-readable problems;
    an empty list means the password is acceptable.

    The policy follows the spirit of NIST SP 800-63B: length is the primary
    control, blocklist known-bad values, and refuse context-specific values
    (the user's own name or email). Composition rules are kept moderate rather
    than punitive, because excessive complexity rules push users toward
    predictable substitutions.
    """
    problems: list[str] = []
    if password is None:
        return ["Password is required."]

    pw = normalise(password)
    min_len = current_app.config["PASSWORD_MIN_LENGTH"]

    if len(pw) < min_len:
        problems.append(f"Password must be at least {min_len} characters long.")
    if len(pw) > 128:
        problems.append("Password must not exceed 128 characters.")
    if not re.search(r"[A-Z]", pw):
        problems.append("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", pw):
        problems.append("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", pw):
        problems.append("Password must contain at least one digit.")
    if not re.search(r"[^A-Za-z0-9]", pw):
        problems.append("Password must contain at least one special character.")

    lowered = pw.lower()
    if is_predictable(pw):
        problems.append("This password is too predictable. Choose something less guessable.")
    if username and len(username) >= 3 and username.lower() in lowered:
        problems.append("Password must not contain your username.")
    if email:
        local = email.split("@")[0]
        if len(local) >= 3 and local.lower() in lowered:
            problems.append("Password must not contain part of your email address.")
    if re.search(r"(.)\1{3,}", pw):
        problems.append("Password must not repeat the same character four or more times.")

    return problems
