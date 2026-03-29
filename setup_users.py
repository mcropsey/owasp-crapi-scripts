#!/usr/bin/env python3
"""
crAPI Lab Setup — Register or Reset Test Users

Logic:
  1. Try to register each user via /signup
  2. If already registered, try login with configured password
  3. If login fails, use forget-password + MailHog OTP to reset to configured password
  4. Print final confirmation table

Target:  https://crapi.cropseyit.com
MailHog: http://crapi.cropseyit.com:8025
"""

import requests
import sys
import re
import time

BASE_URL    = "https://crapi.cropseyit.com"
MAILHOG_URL = "http://crapi.cropseyit.com:8025"

USERS = [
    {"name": "Alice Attacker", "email": "user1@example.com", "password": "User1Pass!1", "number": "5551000001"},
    {"name": "Bob Victim",     "email": "user2@example.com", "password": "User2Pass!2", "number": "5551000002"},
]


def signup(user):
    r = requests.post(f"{BASE_URL}/identity/api/auth/signup", json=user, timeout=10)
    return r.status_code, r.text


def login(email, password):
    r = requests.post(f"{BASE_URL}/identity/api/auth/login",
                      json={"email": email, "password": password}, timeout=10)
    if r.status_code == 200:
        return r.json().get("token")
    return None


def trigger_forgot_password(email):
    r = requests.post(f"{BASE_URL}/identity/api/auth/forget-password",
                      json={"email": email}, timeout=10)
    return r.status_code, r.text


def get_otp_from_mailhog(email):
    """Fetch the most recent OTP for this email from MailHog."""
    try:
        r = requests.get(f"{MAILHOG_URL}/api/v2/messages?limit=50", timeout=5)
        if r.status_code != 200:
            return None
        for msg in r.json().get("items", []):
            raw_to  = " ".join(msg.get("Raw", {}).get("To", []))
            body    = msg.get("Content", {}).get("Body", "")
            if email.lower() in (raw_to + body).lower():
                otps = re.findall(r'\b\d{4}\b', body)
                if otps:
                    return otps[-1]
    except Exception as e:
        print(f"    [MailHog error] {e}")
    return None


def reset_password(email, new_password):
    status, body = trigger_forgot_password(email)
    print(f"    forget-password → HTTP {status}: {body[:80]}")
    if status not in (200, 201):
        return False

    print(f"    Waiting 3s for OTP email...")
    time.sleep(3)

    otp = get_otp_from_mailhog(email)
    if not otp:
        print(f"    Could not auto-retrieve OTP from MailHog.")
        print(f"    Open {MAILHOG_URL} and find the OTP for {email}:")
        otp = input("    Enter OTP: ").strip()

    if not otp:
        return False

    print(f"    OTP: {otp}")
    for ver in ["v3", "v2"]:
        r = requests.post(f"{BASE_URL}/identity/api/auth/{ver}/check-otp",
                          json={"email": email, "otp": otp, "password": new_password}, timeout=10)
        print(f"    check-otp ({ver}) → HTTP {r.status_code}: {r.text[:80]}")
        if r.status_code == 200:
            return True
    return False


def handle_user(user):
    email, password = user["email"], user["password"]
    print(f"\n  User: {user['name']} <{email}>")

    status, body = signup(user)
    if status in (200, 201):
        print(f"  ✅ Registered (HTTP {status})")
    else:
        print(f"  ℹ️  Signup HTTP {status} — user likely exists already")

    token = login(email, password)
    if token:
        print(f"  ✅ Login OK → {token[:50]}...")
        return True

    print(f"  ❌ Login failed — attempting password reset via MailHog OTP...")
    if reset_password(email, password):
        token = login(email, password)
        if token:
            print(f"  ✅ Login OK after reset → {token[:50]}...")
            return True
    print(f"  ❌ Could not authenticate {email}")
    return False


def main():
    print(f"\nTarget:  {BASE_URL}")
    print(f"MailHog: {MAILHOG_URL}")
    print("=" * 54)

    results = [(u["email"], u["password"], handle_user(u)) for u in USERS]

    print(f"\n{'='*54}")
    print("  FINAL STATUS")
    print(f"{'='*54}")
    all_ok = all(ok for _, _, ok in results)
    for email, pw, ok in results:
        print(f"  {'✅' if ok else '❌'}  {email} / {pw}")

    if all_ok:
        print(f"\n  Both users ready — run:  python run_all_tests.py\n")
    else:
        print(f"\n  ⚠️  Fix auth issues above before running tests.")
        print(f"  MailHog: {MAILHOG_URL}\n")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except requests.exceptions.ConnectionError as e:
        print(f"\n[ERROR] Cannot reach {BASE_URL}\n{e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[Aborted]")
        sys.exit(1)
