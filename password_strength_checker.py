#!/usr/bin/env python3
"""Password strength checker with optional Have I Been Pwned k-anonymity lookup."""
import argparse
import hashlib
import re
import urllib.request
import urllib.error
import json
import getpass

def assess(password: str):
    score = 0
    reasons = []
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        reasons.append("Use at least 12 characters; 8 is the minimum baseline.")
    checks = [
        (bool(re.search(r"[a-z]", password)), "lowercase letters"),
        (bool(re.search(r"[A-Z]", password)), "uppercase letters"),
        (bool(re.search(r"\d", password)), "digits"),
        (bool(re.search(r"[^A-Za-z0-9]", password)), "symbols"),
    ]
    for passed, label in checks:
        if passed:
            score += 1
        else:
            reasons.append(f"Add {label}.")
    if re.search(r"(.)\1{2,}", password):
        score -= 1
        reasons.append("Avoid repeating the same character three or more times.")
    if re.search(r"password|qwerty|123456|admin", password, re.I):
        score -= 2
        reasons.append("Avoid common or predictable patterns.")
    score = max(0, min(score, 6))
    category = "Strong" if score >= 5 and len(password) >= 12 else "Moderate" if score >= 3 else "Weak"
    if not reasons:
        reasons.append("Meets the configured length and character-diversity checks.")
    return {"score": score, "max_score": 6, "category": category, "reasons": reasons}

def hibp_count(password: str, timeout: float = 5.0):
    """Check breach corpus using SHA-1 prefix k-anonymity; never sends full password/hash."""
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"Add-Padding": "true", "User-Agent": "AVIP-Password-Strength-Checker"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    for line in body.splitlines():
        parts = line.split(":")
        if len(parts) == 2 and parts[0].strip().upper() == suffix:
            return int(parts[1].strip())
    return 0

def main():
    parser = argparse.ArgumentParser(description="Password strength and breach checker")
    parser.add_argument("--hibp", action="store_true", help="Check Have I Been Pwned Passwords API")
    args = parser.parse_args()
    password = getpass.getpass("Password (input hidden): ")
    result = assess(password)
    print(f"Strength: {result['category']} ({result['score']}/{result['max_score']})")
    for reason in result["reasons"]:
        print(f"- {reason}")
    if args.hibp:
        try:
            count = hibp_count(password)
            if count:
                print(f"COMPROMISED: found {count:,} times in the Pwned Passwords corpus.")
            else:
                print("No match found in the checked Pwned Passwords corpus.")
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            print(f"Breach lookup unavailable: {exc}. Local strength assessment is still complete.")

if __name__ == "__main__":
    main()
