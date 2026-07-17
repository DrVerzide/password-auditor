"""Breach exposure check via the Have I Been Pwned (HIBP) Pwned Passwords API.

Privacy: uses the k-anonymity model. Only the first 5 characters of the
SHA-1 hash of the password are ever sent to the API; the full password
(or its full hash) never leaves the machine.

API docs: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

from __future__ import annotations

import hashlib

import requests

API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
TIMEOUT_SECONDS = 10


class BreachCheckError(RuntimeError):
    """Raised when the HIBP API cannot be reached or returns an error."""


def check_breach_count(password: str) -> int:
    """Return how many times the password appears in known breaches.

    Returns 0 if the password was not found. Raises BreachCheckError on
    network or API failures so callers can distinguish "not found" from
    "could not check".
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        response = requests.get(
            API_URL.format(prefix=prefix),
            headers={"Add-Padding": "true", "User-Agent": "password-auditor"},
            timeout=TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise BreachCheckError(f"Could not query HIBP API: {exc}") from exc

    for line in response.text.splitlines():
        candidate_suffix, _, count = line.partition(":")
        if candidate_suffix == suffix:
            return int(count)
    return 0
