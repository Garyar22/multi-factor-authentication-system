"""
Unit tests for TOTP generation, the clock-skew window and replay prevention.

These are the tests that substantiate project objective 5 and acceptance
criterion 4 (invalid, expired and reused codes are rejected as designed).
"""

import time

import pyotp

from app.security.totp import (
    current_counter,
    find_matching_counter,
    generate_code,
    generate_secret,
    provisioning_uri,
    verify_code,
)


class TestSecretAndUri:
    def test_secret_is_base32_and_long_enough(self, app):
        with app.app_context():
            secret = generate_secret()
        assert len(secret) == 32  # 160 bits in base32
        assert set(secret) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")

    def test_secrets_are_unique_per_call(self, app):
        with app.app_context():
            secrets_seen = {generate_secret() for _ in range(50)}
        assert len(secrets_seen) == 50

    def test_provisioning_uri_is_well_formed(self, app):
        with app.app_context():
            secret = generate_secret()
            uri = provisioning_uri(secret, "student@example.com")
        assert uri.startswith("otpauth://totp/")
        assert f"secret={secret}" in uri
        assert "issuer=" in uri

    def test_generated_code_matches_a_standard_library(self, app):
        """Cross-check against pyotp directly, so the wrapper is not trusted blindly."""
        with app.app_context():
            secret = generate_secret()
            at = 1_700_000_000
            assert generate_code(secret, at=at) == pyotp.TOTP(secret).at(at)


class TestVerification:
    def test_current_code_accepted(self, app):
        with app.app_context():
            secret = generate_secret()
            assert verify_code(secret, generate_code(secret))[0] is True

    def test_wrong_code_rejected(self, app):
        with app.app_context():
            secret = generate_secret()
            accepted, _, reason = verify_code(secret, "000000")
            # 000000 could in principle be the real code; regenerate if so.
            if generate_code(secret) == "000000":
                accepted, _, reason = verify_code(secret, "111111")
            assert accepted is False
            assert reason == "invalid"

    def test_malformed_codes_rejected(self, app):
        with app.app_context():
            secret = generate_secret()
            for bad in ("", "12345", "1234567", "abcdef", "12 34 5", None, "12345a"):
                assert verify_code(secret, bad)[0] is False

    def test_code_with_spaces_is_accepted(self, app):
        """Users paste codes with spaces; the server should cope."""
        with app.app_context():
            secret = generate_secret()
            code = generate_code(secret)
            spaced = f"{code[:3]} {code[3:]}"
            assert verify_code(secret, spaced)[0] is True

    def test_code_from_another_secret_rejected(self, app):
        with app.app_context():
            a, b = generate_secret(), generate_secret()
            assert verify_code(a, generate_code(b))[0] is False


class TestClockSkewWindow:
    def test_previous_and_next_step_accepted_within_window(self, app):
        with app.app_context():
            app.config["TOTP_VALID_WINDOW"] = 1
            secret = generate_secret()
            now = time.time()
            interval = app.config["TOTP_INTERVAL"]
            for offset in (-interval, 0, interval):
                code = generate_code(secret, at=now + offset)
                assert verify_code(secret, code, at=now)[0] is True, offset

    def test_code_outside_the_window_rejected(self, app):
        with app.app_context():
            app.config["TOTP_VALID_WINDOW"] = 1
            secret = generate_secret()
            now = time.time()
            interval = app.config["TOTP_INTERVAL"]
            # Two steps away is outside a window of one step.
            stale = generate_code(secret, at=now - 2 * interval)
            assert verify_code(secret, stale, at=now)[0] is False

    def test_expired_code_rejected(self, app):
        """A code from five minutes ago must never work."""
        with app.app_context():
            secret = generate_secret()
            now = time.time()
            old = generate_code(secret, at=now - 300)
            assert verify_code(secret, old, at=now)[0] is False

    def test_window_of_zero_accepts_only_the_current_step(self, app):
        with app.app_context():
            app.config["TOTP_VALID_WINDOW"] = 0
            secret = generate_secret()
            now = time.time()
            interval = app.config["TOTP_INTERVAL"]
            assert verify_code(secret, generate_code(secret, at=now), at=now)[0] is True
            previous = generate_code(secret, at=now - interval)
            assert verify_code(secret, previous, at=now)[0] is False

    def test_matching_counter_is_returned(self, app):
        with app.app_context():
            secret = generate_secret()
            now = time.time()
            counter = find_matching_counter(secret, generate_code(secret, at=now), at=now)
            assert counter == current_counter(now)


class TestReplayPrevention:
    def test_same_code_refused_a_second_time(self, app):
        with app.app_context():
            secret = generate_secret()
            now = time.time()
            code = generate_code(secret, at=now)

            accepted, counter, reason = verify_code(secret, code, last_used_counter=None, at=now)
            assert (accepted, reason) == (True, "ok")

            # Second presentation, with the counter now recorded as spent.
            accepted, _, reason = verify_code(
                secret, code, last_used_counter=counter, at=now
            )
            assert accepted is False
            assert reason == "replay"

    def test_earlier_step_refused_after_a_later_one_was_used(self, app):
        """A captured older code must not work once a newer one has been used."""
        with app.app_context():
            app.config["TOTP_VALID_WINDOW"] = 1
            secret = generate_secret()
            now = time.time()
            interval = app.config["TOTP_INTERVAL"]

            older = generate_code(secret, at=now - interval)
            used_counter = current_counter(now)

            accepted, _, reason = verify_code(
                secret, older, last_used_counter=used_counter, at=now
            )
            assert accepted is False
            assert reason == "replay"

    def test_next_step_code_accepted_after_a_replay_block(self, app):
        """The legitimate user must be able to log in again with a fresh code."""
        with app.app_context():
            secret = generate_secret()
            now = time.time()
            interval = app.config["TOTP_INTERVAL"]

            first = generate_code(secret, at=now)
            _, counter, _ = verify_code(secret, first, at=now)

            later = now + interval
            fresh = generate_code(secret, at=later)
            accepted, new_counter, reason = verify_code(
                secret, fresh, last_used_counter=counter, at=later
            )
            assert (accepted, reason) == (True, "ok")
            assert new_counter > counter
