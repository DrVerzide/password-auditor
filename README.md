# password-auditor

A command-line tool that audits password strength **offline** and optionally checks whether a password has appeared in known data breaches using the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) Pwned Passwords API.

## Features

- **Entropy-based scoring (0–100)** — estimates the character pool and computes Shannon entropy.
- **Pattern detection** — flags repeated characters, keyboard sequences (`qwerty`, `asdfgh`…), ascending digit runs and embedded years.
- **Common-password check** — instantly rejects passwords from a built-in top-leaked list.
- **Breach exposure check with k-anonymity** — only the first 5 characters of the SHA-1 hash are sent to the HIBP API. The password itself **never leaves your machine**.
- **Safe input** — the password is read with `getpass`, so it is never echoed to the terminal or stored in shell history.

## Installation

```bash
git clone https://github.com/<your-user>/password-auditor.git
cd password-auditor
pip install .
```

For development (editable install + tests):

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Offline audit only
password-auditor

# Audit + breach check against HIBP
password-auditor --check-breach
```

Example output:

```
Password to audit (input hidden):

  Strength : [####################----------] 68/100  (Good)
  Entropy  : 78.7 bits
  [+] Consider 12+ characters for long-term safety.

  [+] Not found in known breaches.
```

You can also run it without installing:

```bash
python -m password_auditor --check-breach
```

## How the breach check protects your password (k-anonymity)

1. The password is hashed locally with SHA-1.
2. Only the **first 5 hex characters** of the hash are sent to `api.pwnedpasswords.com/range/<prefix>`.
3. The API returns every known hash suffix matching that prefix (hundreds of candidates).
4. The comparison against the full hash happens **locally**.

This means neither the password nor enough information to reconstruct it is ever transmitted.

## Running the tests

```bash
pytest
```

The test suite covers the scoring logic, pattern detection, and mocks the HIBP API — including a test asserting that the full hash is never sent over the network.

## Project structure

```
src/password_auditor/
├── analyzer.py   # entropy, pattern detection, scoring
├── breach.py     # HIBP k-anonymity client
└── cli.py        # argparse CLI entry point
tests/
```

## License

MIT
