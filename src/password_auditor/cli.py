"""Command-line interface for password-auditor."""

from __future__ import annotations

import argparse
import getpass
import sys

from .analyzer import audit_password
from .breach import BreachCheckError, check_breach_count

BAR_WIDTH = 30


def _score_bar(score: int) -> str:
    filled = round(score / 100 * BAR_WIDTH)
    return "[" + "#" * filled + "-" * (BAR_WIDTH - filled) + f"] {score}/100"


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="password-auditor",
        description=(
            "Audit password strength offline and optionally check breach "
            "exposure via the Have I Been Pwned API (k-anonymity: the "
            "password never leaves your machine)."
        ),
    )
    parser.add_argument(
        "--check-breach",
        action="store_true",
        help="also query the HIBP Pwned Passwords API",
    )
    args = parser.parse_args(argv)

    # getpass keeps the password out of the terminal echo and shell history.
    password = getpass.getpass("Password to audit (input hidden): ")

    result = audit_password(password)

    print()
    print(f"  Strength : {_score_bar(result.score)}  ({result.verdict})")
    print(f"  Entropy  : {result.entropy_bits} bits")

    for warning in result.warnings:
        print(f"  [!] {warning}")
    for suggestion in result.suggestions:
        print(f"  [+] {suggestion}")

    if args.check_breach:
        print()
        try:
            count = check_breach_count(password)
        except BreachCheckError as exc:
            print(f"  [!] Breach check failed: {exc}")
            return 2
        if count:
            print(f"  [!] Found in {count:,} known breaches. Do NOT use it.")
        else:
            print("  [+] Not found in known breaches.")

    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
