import pytest

from password_auditor.analyzer import (
    audit_password,
    charset_size,
    shannon_entropy,
)


class TestCharsetSize:
    def test_lowercase_only(self):
        assert charset_size("abc") == 26

    def test_mixed_case(self):
        assert charset_size("aB") == 52

    def test_full_mix(self):
        assert charset_size("aB3!") == 26 + 26 + 10 + 33

    def test_empty(self):
        assert charset_size("") == 0


class TestEntropy:
    def test_empty_password_has_zero_entropy(self):
        assert shannon_entropy("") == 0.0

    def test_longer_password_has_more_entropy(self):
        assert shannon_entropy("abcdefgh") > shannon_entropy("abcd")

    def test_wider_charset_has_more_entropy(self):
        assert shannon_entropy("aB3!aB3!") > shannon_entropy("abcdabcd")


class TestAuditPassword:
    def test_empty_password(self):
        result = audit_password("")
        assert result.score == 0
        assert result.verdict == "Empty"

    def test_common_password_scores_zero(self):
        result = audit_password("password")
        assert result.score == 0
        assert result.verdict == "Very weak"

    def test_common_password_case_insensitive(self):
        assert audit_password("QWERTY").score == 0

    def test_short_password_capped(self):
        result = audit_password("xK9!p")
        assert result.score <= 25
        assert any("8 characters" in w for w in result.warnings)

    def test_strong_password(self):
        result = audit_password("mV9!qLx#2rTz&5wP")
        assert result.score >= 80
        assert result.verdict == "Strong"

    def test_keyboard_sequence_flagged(self):
        result = audit_password("Xqwerty!29houses")
        assert any("keyboard sequence" in w for w in result.warnings)

    def test_digit_sequence_flagged(self):
        result = audit_password("Horse1234Battery!")
        assert any("digit sequence" in w for w in result.warnings)

    def test_year_flagged(self):
        result = audit_password("Summer2024vibes!")
        assert any("year" in w for w in result.warnings)

    def test_suggestions_for_missing_classes(self):
        result = audit_password("onlylowercaseletters")
        joined = " ".join(result.suggestions)
        assert "uppercase" in joined
        assert "digits" in joined
        assert "symbols" in joined

    @pytest.mark.parametrize("pw", ["a", "ab", "abc1234", "Pa$1"])
    def test_short_passwords_never_strong(self, pw):
        assert audit_password(pw).verdict in {"Very weak", "Weak", "Fair"}
