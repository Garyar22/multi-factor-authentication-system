"""Unit tests for secret encryption at rest and recovery-code handling."""

import pytest
from cryptography.fernet import Fernet, InvalidToken

from app.extensions import db
from app.models import RecoveryCode, User
from app.security.crypto import (
    EncryptionKeyMissing,
    constant_time_equals,
    decrypt_secret,
    encrypt_secret,
    generate_url_token,
    sha256_hex,
    try_decrypt_secret,
)
from app.security.recovery import (
    consume_recovery_code,
    generate_recovery_codes,
    normalise_code,
)


class TestEncryption:
    def test_roundtrip(self, app):
        with app.app_context():
            assert decrypt_secret(encrypt_secret("JBSWY3DPEHPK3PXP")) == "JBSWY3DPEHPK3PXP"

    def test_ciphertext_hides_the_plaintext(self, app):
        with app.app_context():
            ciphertext = encrypt_secret("JBSWY3DPEHPK3PXP")
        assert "JBSWY3DPEHPK3PXP" not in ciphertext

    def test_same_plaintext_encrypts_differently_each_time(self, app):
        """Fernet includes a random IV, so ciphertexts must not repeat."""
        with app.app_context():
            assert encrypt_secret("SAME") != encrypt_secret("SAME")

    def test_tampered_ciphertext_is_rejected(self, app):
        """Authenticated encryption must refuse modified data, not decrypt it."""
        with app.app_context():
            ciphertext = encrypt_secret("JBSWY3DPEHPK3PXP")
            tampered = ciphertext[:-4] + ("AAAA" if ciphertext[-4:] != "AAAA" else "BBBB")
            with pytest.raises(InvalidToken):
                decrypt_secret(tampered)
            assert try_decrypt_secret(tampered) is None

    def test_wrong_key_cannot_decrypt(self, app):
        with app.app_context():
            ciphertext = encrypt_secret("JBSWY3DPEHPK3PXP")
            app.config["MFA_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
            assert try_decrypt_secret(ciphertext) is None

    def test_missing_key_raises_a_clear_error(self, app):
        with app.app_context():
            app.config["MFA_ENCRYPTION_KEY"] = None
            with pytest.raises(EncryptionKeyMissing):
                encrypt_secret("x")

    def test_malformed_key_raises(self, app):
        with app.app_context():
            app.config["MFA_ENCRYPTION_KEY"] = "not-a-valid-fernet-key"
            with pytest.raises(EncryptionKeyMissing):
                encrypt_secret("x")


class TestTokenHelpers:
    def test_tokens_are_unique_and_long(self):
        tokens = {generate_url_token() for _ in range(100)}
        assert len(tokens) == 100
        assert all(len(t) >= 40 for t in tokens)

    def test_sha256_is_stable_and_one_way(self):
        assert sha256_hex("abc") == sha256_hex("abc")
        assert sha256_hex("abc") != sha256_hex("abd")
        assert len(sha256_hex("abc")) == 64
        assert "abc" not in sha256_hex("abc")

    def test_constant_time_equals(self):
        assert constant_time_equals("abc", "abc") is True
        assert constant_time_equals("abc", "abd") is False
        assert constant_time_equals("", "") is True
        assert constant_time_equals(None, None) is True


class TestRecoveryCodes:
    def test_generates_the_configured_number(self, app, user):
        with app.app_context():
            u = db.session.get(User, user)
            codes = generate_recovery_codes(u)
            db.session.commit()
        assert len(codes) == app.config["RECOVERY_CODE_COUNT"]

    def test_codes_are_unique_and_well_formatted(self, app, user):
        with app.app_context():
            u = db.session.get(User, user)
            codes = generate_recovery_codes(u)
            db.session.commit()
        assert len(set(codes)) == len(codes)
        for code in codes:
            assert len(code) == 11 and code[5] == "-"
            # Ambiguous characters must not appear.
            assert not set(code) & set("01OIL")

    def test_only_hashes_are_stored(self, app, user):
        with app.app_context():
            u = db.session.get(User, user)
            codes = generate_recovery_codes(u)
            db.session.commit()
            stored = [row.code_hash for row in RecoveryCode.query.filter_by(user_id=u.id)]
        assert all(h.startswith("$argon2") for h in stored)
        for code in codes:
            assert not any(code in h for h in stored)

    def test_valid_code_is_consumed_once(self, app, user):
        with app.app_context():
            u = db.session.get(User, user)
            codes = generate_recovery_codes(u)
            db.session.commit()

            assert consume_recovery_code(u, codes[0]) is True
            db.session.commit()
            db.session.refresh(u)
            # The very same code must now fail.
            assert consume_recovery_code(u, codes[0]) is False

    def test_remaining_codes_still_work(self, app, user):
        with app.app_context():
            u = db.session.get(User, user)
            codes = generate_recovery_codes(u)
            db.session.commit()
            consume_recovery_code(u, codes[0])
            db.session.commit()
            db.session.refresh(u)
            assert consume_recovery_code(u, codes[1]) is True
            db.session.commit()
            db.session.refresh(u)
            assert u.unused_recovery_code_count() == len(codes) - 2

    def test_unknown_code_rejected(self, app, user):
        with app.app_context():
            u = db.session.get(User, user)
            generate_recovery_codes(u)
            db.session.commit()
            assert consume_recovery_code(u, "ZZZZZ-ZZZZZ") is False
            assert consume_recovery_code(u, "") is False

    def test_regeneration_invalidates_the_old_set(self, app, user):
        with app.app_context():
            u = db.session.get(User, user)
            first = generate_recovery_codes(u)
            db.session.commit()
            db.session.refresh(u)

            second = generate_recovery_codes(u)
            db.session.commit()
            db.session.refresh(u)

            assert consume_recovery_code(u, first[0]) is False
            assert consume_recovery_code(u, second[0]) is True

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("abcde-fghjk", "ABCDE-FGHJK"),
            ("ABCDEFGHJK", "ABCDE-FGHJK"),
            (" abcde fghjk ", "ABCDE-FGHJK"),
            ("abcde-FGHJK", "ABCDE-FGHJK"),
        ],
    )
    def test_input_normalisation(self, raw, expected):
        assert normalise_code(raw) == expected

    def test_case_and_dash_insensitive_consumption(self, app, user):
        with app.app_context():
            u = db.session.get(User, user)
            codes = generate_recovery_codes(u)
            db.session.commit()
            messy = codes[0].lower().replace("-", " ")
            assert consume_recovery_code(u, messy) is True
