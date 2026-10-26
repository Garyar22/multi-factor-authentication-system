"""Unit tests for password hashing and the password policy."""

import pytest

from app.security.passwords import (
    hash_password,
    needs_rehash,
    normalise,
    validate_password_strength,
    verify_password,
)


class TestHashing:
    def test_hash_is_argon2id_and_not_the_password(self, app):
        with app.app_context():
            digest = hash_password("Correct#Horse42!")
        assert digest.startswith("$argon2id$")
        assert "Correct#Horse42!" not in digest

    def test_same_password_hashes_differently(self, app):
        """A per-hash random salt means identical passwords must not collide."""
        with app.app_context():
            a = hash_password("Correct#Horse42!")
            b = hash_password("Correct#Horse42!")
        assert a != b

    def test_verify_accepts_correct_password(self, app):
        with app.app_context():
            digest = hash_password("Correct#Horse42!")
            assert verify_password(digest, "Correct#Horse42!") is True

    def test_verify_rejects_wrong_password(self, app):
        with app.app_context():
            digest = hash_password("Correct#Horse42!")
            assert verify_password(digest, "Correct#Horse43!") is False

    def test_verify_rejects_empty_and_malformed(self, app):
        with app.app_context():
            assert verify_password("", "anything") is False
            assert verify_password("not-a-hash", "anything") is False
            assert verify_password("$argon2id$garbage", "anything") is False

    def test_unicode_normalisation(self, app):
        """Visually identical Unicode forms must verify against each other."""
        composed = "Café#Strong42!"            # é as one code point
        decomposed = "Café#Strong42!"    # e + combining acute
        assert normalise(composed) == normalise(decomposed)
        with app.app_context():
            digest = hash_password(composed)
            assert verify_password(digest, decomposed) is True

    def test_needs_rehash_detects_weaker_parameters(self, app):
        with app.app_context():
            digest = hash_password("Correct#Horse42!")
            assert needs_rehash(digest) is False
            app.config["ARGON2_TIME_COST"] = app.config["ARGON2_TIME_COST"] + 2
            assert needs_rehash(digest) is True


class TestDummyHash:
    """
    The dummy hash equalises the cost of a login attempt for a username that
    does not exist. If it were malformed, argon2-cffi would reject it in
    microseconds and unknown usernames would answer far faster than known
    ones — a reliable account-enumeration oracle. These tests pin that down.
    """

    def test_dummy_hash_is_a_real_argon2id_hash(self, app):
        from app.security.passwords import dummy_hash

        with app.app_context():
            value = dummy_hash()
        assert value.startswith("$argon2id$")

    def test_verifying_against_it_fails_but_does_real_work(self, app):
        import time

        from app.security.passwords import dummy_hash

        with app.app_context():
            # Raise the cost so the difference is unmistakable even on a fast machine.
            app.config["ARGON2_TIME_COST"] = 2
            app.config["ARGON2_MEMORY_COST"] = 32768
            value = dummy_hash()

            assert verify_password(value, "anything at all") is False

            start = time.perf_counter()
            verify_password(value, "anything at all")
            dummy_cost = time.perf_counter() - start

            real = hash_password("Reference#Password42!")
            start = time.perf_counter()
            verify_password(real, "WrongPassword#99!")
            real_cost = time.perf_counter() - start

        # The dummy path must be within the same order of magnitude as a real
        # verification, not thousands of times faster.
        assert dummy_cost > real_cost * 0.4, (dummy_cost, real_cost)

    def test_a_malformed_hash_would_be_far_too_cheap(self, app):
        """Demonstrates the bug this guards against, so it cannot silently return."""
        import time

        with app.app_context():
            app.config["ARGON2_TIME_COST"] = 2
            app.config["ARGON2_MEMORY_COST"] = 32768
            malformed = "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$0000000000"

            start = time.perf_counter()
            verify_password(malformed, "anything")
            malformed_cost = time.perf_counter() - start

            real = hash_password("Reference#Password42!")
            start = time.perf_counter()
            verify_password(real, "WrongPassword#99!")
            real_cost = time.perf_counter() - start

        assert malformed_cost < real_cost * 0.2, (malformed_cost, real_cost)

    def test_dummy_hash_is_cached_per_process(self, app):
        from app.security.passwords import dummy_hash

        with app.app_context():
            assert dummy_hash() == dummy_hash()

    def test_dummy_hash_changes_when_cost_parameters_change(self, app):
        from app.security.passwords import dummy_hash

        with app.app_context():
            first = dummy_hash()
            app.config["ARGON2_TIME_COST"] = app.config["ARGON2_TIME_COST"] + 1
            assert dummy_hash() != first


class TestPolicy:
    def test_strong_password_accepted(self, app):
        with app.app_context():
            assert validate_password_strength("Garoowe#Harbour91!") == []

    @pytest.mark.parametrize(
        "password,expected_fragment",
        [
            ("Short#1a", "at least 12"),
            ("alllowercase12!", "uppercase"),
            ("ALLUPPERCASE12!", "lowercase"),
            ("NoDigitsHere!!!", "digit"),
            ("NoSymbols12345", "special character"),
            ("aaaaAAAA1111!", "four or more"),
        ],
    )
    def test_weak_passwords_rejected(self, app, password, expected_fragment):
        with app.app_context():
            problems = validate_password_strength(password)
        assert any(expected_fragment in p for p in problems), problems

    def test_common_password_rejected(self, app):
        with app.app_context():
            problems = validate_password_strength("Password123!")
        assert problems  # fails on composition and/or the blocklist

    def test_password_containing_username_rejected(self, app):
        with app.app_context():
            problems = validate_password_strength("Alice#Secret42!", username="alice")
        assert any("username" in p for p in problems)

    def test_password_containing_email_local_part_rejected(self, app):
        with app.app_context():
            problems = validate_password_strength(
                "Yahye#Secret42!", email="yahye@example.com"
            )
        assert any("email" in p for p in problems)

    def test_over_long_password_rejected(self, app):
        with app.app_context():
            problems = validate_password_strength("Aa1!" + "x" * 200)
        assert any("128" in p for p in problems)

    def test_none_password_rejected(self, app):
        with app.app_context():
            assert validate_password_strength(None) == ["Password is required."]
