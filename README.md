# AVIP 2026 — Cybersecurity Python Tasks
## Task 2 — Password Strength Checker

Features:
- Hidden terminal password input.
- Documented length, character-diversity, repetition, and common-pattern checks.
- Optional Have I Been Pwned Pwned Passwords lookup using range-based k-anonymity: only the first five characters of the SHA-1 hash are sent; the full password and full hash are not transmitted.

Usage:
```bash
python password_strength_checker.py
python password_strength_checker.py --hibp
```

The breach lookup requires internet access. A match count refers to appearances in the Pwned Passwords corpus, not the number of distinct data breaches.

## Tests

Run:
```bash
python -m unittest -v
```

## Ethical and Security Notes

- Use the password checker locally and never enter a password you currently use on a critical account into an untrusted environment.
- The optional breach lookup uses the Have I Been Pwned range endpoint and does not submit the plaintext password.
- The Caesar cracker uses a heuristic; verify output before relying on it.

## Repository Naming

Suggested repository name: `CS_1_CaesarCipher_byte` and `CS_2_PasswordStrengthChecker_byte` if submitted as separate repositories, following the naming pattern in the internship document.
