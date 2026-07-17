import hashlib
from unittest.mock import MagicMock, patch

import pytest
import requests

from password_auditor.breach import BreachCheckError, check_breach_count


def _fake_response_for(password: str, count: int) -> MagicMock:
    """Build a fake HIBP response that contains the password's hash suffix."""
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    suffix = sha1[5:]
    body = f"0000000000000000000000000000000000A:12\r\n{suffix}:{count}"
    response = MagicMock()
    response.text = body
    response.raise_for_status = MagicMock()
    return response


@patch("password_auditor.breach.requests.get")
def test_found_password_returns_count(mock_get):
    mock_get.return_value = _fake_response_for("hunter2", 17)
    assert check_breach_count("hunter2") == 17


@patch("password_auditor.breach.requests.get")
def test_not_found_returns_zero(mock_get):
    response = MagicMock()
    response.text = "0000000000000000000000000000000000A:12"
    response.raise_for_status = MagicMock()
    mock_get.return_value = response
    assert check_breach_count("some-password") == 0


@patch("password_auditor.breach.requests.get")
def test_only_hash_prefix_is_sent(mock_get):
    """The full password or full hash must never appear in the request URL."""
    mock_get.return_value = _fake_response_for("supersecret", 1)
    check_breach_count("supersecret")

    url = mock_get.call_args.args[0]
    sha1 = hashlib.sha1(b"supersecret").hexdigest().upper()
    assert sha1[:5] in url
    assert sha1 not in url
    assert "supersecret" not in url


@patch("password_auditor.breach.requests.get")
def test_network_error_raises_breach_check_error(mock_get):
    mock_get.side_effect = requests.ConnectionError("boom")
    with pytest.raises(BreachCheckError):
        check_breach_count("whatever")
