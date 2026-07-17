"""Core password strength analysis.

Scores a password from 0 to 100 based on entropy, character variety,
common patterns and presence in a list of frequently used passwords.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field

# Small built-in sample of the most common leaked passwords.
# A real deployment would load a larger wordlist (e.g. rockyou top-10k).
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "shadow", "master",
    "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "superman", "1qaz2wsx", "7777777", "121212",
    "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan",
    "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster", "soccer",
    "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou",
    "2000", "charlie", "robert", "thomas", "hockey", "ranger",
    "daniel", "starwars", "klaster", "112233", "george", "computer",
    "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555",
    "11111111", "131313", "freedom", "777777", "pass", "maggie",
    "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese",
    "amanda", "summer", "love", "ashley", "nicole", "chelsea",
    "biteme", "matthew", "access", "yankees", "987654321", "dallas",
    "austin", "thunder", "taylor", "matrix", "admin", "welcome",
    "password1", "p@ssw0rd", "root", "toor", "secret", "test",
}

KEYBOARD_SEQUENCES = ("qwerty", "asdfgh", "zxcvbn", "qwertz", "azerty")


@dataclass
class AuditResult:
    """Outcome of a password audit."""

    score: int
    entropy_bits: float
    verdict: str
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)


def charset_size(password: str) -> int:
    """Estimate the size of the character pool the password draws from."""
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"\d", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        size += 33  # printable ASCII symbols
    return size


def shannon_entropy(password: str) -> float:
    """Entropy in bits assuming each character is drawn from its charset."""
    pool = charset_size(password)
    if pool == 0 or not password:
        return 0.0
    return len(password) * math.log2(pool)


def _sequence_penalty(password: str) -> tuple[int, list[str]]:
    """Detect predictable patterns; return (penalty, warnings)."""
    penalty = 0
    warnings: list[str] = []
    lower = password.lower()

    if re.search(r"(.)\1{2,}", password):
        penalty += 10
        warnings.append("Contains repeated characters (e.g. 'aaa').")

    for seq in KEYBOARD_SEQUENCES:
        if seq in lower:
            penalty += 15
            warnings.append(f"Contains keyboard sequence '{seq}'.")
            break

    digits = "0123456789"
    if any(digits[i : i + 4] in password for i in range(len(digits) - 3)):
        penalty += 15
        warnings.append("Contains an ascending digit sequence (e.g. '1234').")

    if re.search(r"(19|20)\d{2}", password):
        penalty += 10
        warnings.append("Contains what looks like a year.")

    return penalty, warnings


def audit_password(password: str) -> AuditResult:
    """Run the full offline audit and return a scored result."""
    if not password:
        return AuditResult(
            score=0,
            entropy_bits=0.0,
            verdict="Empty",
            warnings=["Password is empty."],
            suggestions=["Choose a password of at least 12 characters."],
        )

    warnings: list[str] = []
    suggestions: list[str] = []

    if password.lower() in COMMON_PASSWORDS:
        return AuditResult(
            score=0,
            entropy_bits=shannon_entropy(password),
            verdict="Very weak",
            warnings=["This is one of the most common leaked passwords."],
            suggestions=["Never use dictionary or top-list passwords."],
        )

    entropy = shannon_entropy(password)
    # Map entropy to a 0-100 base score; ~80 bits is considered strong.
    score = min(100, int(entropy / 80 * 100))

    penalty, pattern_warnings = _sequence_penalty(password)
    score = max(0, score - penalty)
    warnings.extend(pattern_warnings)

    if len(password) < 8:
        warnings.append("Shorter than 8 characters.")
        suggestions.append("Use at least 12 characters.")
        score = min(score, 25)
    elif len(password) < 12:
        suggestions.append("Consider 12+ characters for long-term safety.")

    if not re.search(r"[A-Z]", password):
        suggestions.append("Add uppercase letters.")
    if not re.search(r"\d", password):
        suggestions.append("Add digits.")
    if not re.search(r"[^a-zA-Z0-9]", password):
        suggestions.append("Add symbols (e.g. !, %, #).")

    if score >= 80:
        verdict = "Strong"
    elif score >= 60:
        verdict = "Good"
    elif score >= 40:
        verdict = "Fair"
    elif score >= 20:
        verdict = "Weak"
    else:
        verdict = "Very weak"

    return AuditResult(
        score=score,
        entropy_bits=round(entropy, 1),
        verdict=verdict,
        warnings=warnings,
        suggestions=suggestions,
    )
