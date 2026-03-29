#!/usr/bin/env python3
"""
OWASP API Security Top 10:2023 - API8: Security Misconfiguration
Target: crAPI running on Docker (default port 8888)

Tests for:
  - Missing/misconfigured CORS headers
  - Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
  - Exposed debug endpoints or stack traces
  - Verbose error messages revealing internals
  - Open API spec exposure (unauthenticated)
  - Default credentials acceptance
  - HTTP instead of HTTPS in use
"""

import requests
import json
import sys

from crapi_config import BASE_URL, USER1_EMAIL, USER1_PASSWORD, USER2_EMAIL, USER2_PASSWORD
USER_EMAIL = USER1_EMAIL
USER_PASSWORD = USER1_PASSWORD


# Simulated attacker origin for CORS test
ATTACKER_ORIGIN = "https://evil.attacker.com"


def test_cors_misconfiguration():
    """
    API8 Test: Does the API reflect attacker origins in CORS headers?
    A misconfigured API echoes back the Origin header, allowing cross-origin data theft.
    """
    print(f"\n[API8:Misconfig] CORS Policy Check")

    endpoints = [
        "/identity/api/auth/login",
        "/community/api/v2/community/posts/recent",
        "/workshop/api/shop/products",
    ]

    vulnerable = False
    for path in endpoints:
        url = f"{BASE_URL}{path}"
        headers = {"Origin": ATTACKER_ORIGIN}
        r = requests.options(url, headers=headers)
        acao = r.headers.get("Access-Control-Allow-Origin", "NOT SET")
        acac = r.headers.get("Access-Control-Allow-Credentials", "NOT SET")

        print(f"\n  OPTIONS {path}")
        print(f"  HTTP {r.status_code}")
        print(f"  Access-Control-Allow-Origin:      {acao}")
        print(f"  Access-Control-Allow-Credentials: {acac}")

        if acao == "*":
            print(f"  [VULNERABLE] Wildcard CORS — allows any origin!")
            vulnerable = True
        elif ATTACKER_ORIGIN in acao:
            print(f"  [VULNERABLE] Reflected attacker origin in ACAO header!")
            vulnerable = True
            if acac.lower() == "true":
                print(f"  [CRITICAL] Credentials also allowed! Cross-origin session theft possible!")
        else:
            print(f"  [PROTECTED] Origin not reflected")

    return vulnerable


def test_security_headers():
    """
    API8 Test: Check for presence of essential HTTP security headers.
    """
    print(f"\n[API8:Misconfig] Security Headers Check")

    r = requests.get(f"{BASE_URL}/", allow_redirects=True)
    print(f"  GET / → HTTP {r.status_code}")

    security_headers = {
        "Strict-Transport-Security":    "HSTS",
        "Content-Security-Policy":      "CSP",
        "X-Frame-Options":              "Clickjacking protection",
        "X-Content-Type-Options":       "MIME sniffing protection",
        "Referrer-Policy":              "Referrer Policy",
        "Permissions-Policy":           "Permissions Policy",
        "X-XSS-Protection":             "XSS Protection (legacy)",
        "Cache-Control":                "Cache Control",
    }

    missing = []
    present = []
    for header, description in security_headers.items():
        value = r.headers.get(header)
        if value:
            present.append((header, value))
            print(f"  [OK]      {header}: {value[:80]}")
        else:
            missing.append(header)
            print(f"  [MISSING] {header} ({description})")

    if missing:
        print(f"\n  [VULNERABLE] {len(missing)}/{len(security_headers)} security headers missing!")
        return True
    else:
        print(f"\n  [PROTECTED] All security headers present")
        return False


def test_verbose_error_messages():
    """
    API8 Test: Do error responses expose stack traces or internal details?
    """
    print(f"\n[API8:Misconfig] Verbose Error Message Detection")

    # Send malformed input to trigger errors
    probes = [
        ("POST", "/identity/api/auth/login",            {"email": "' OR 1=1--", "password": "x"}),
        ("POST", "/identity/api/auth/login",            {"email": None, "password": None}),
        ("GET",  "/identity/api/v2/vehicle/99999999",   None),
        ("POST", "/community/api/v2/community/posts",   {"title": None, "body": {"nested": "object"}}),
    ]

    verbose_keywords = [
        "traceback", "stack trace", "exception", "at line", "syntax error",
        "java.lang", "org.springframework", "django", "flask", "express",
        "MongoError", "SQLException", "NullPointerException", "undefined",
        "TypeError", "psycopg2", "pymongo"
    ]

    vulnerable = False
    for method, path, body in probes:
        url = f"{BASE_URL}{path}"
        if method == "POST":
            r = requests.post(url, json=body)
        else:
            r = requests.get(url)

        response_text = r.text.lower()
        found_keywords = [kw for kw in verbose_keywords if kw.lower() in response_text]

        print(f"\n  {method} {path}")
        print(f"  HTTP {r.status_code}", end="")
        if found_keywords:
            print(f" ← [VULNERABLE] Verbose error! Keywords found: {found_keywords}")
            print(f"  Response preview: {r.text[:200]}")
            vulnerable = True
        else:
            print(f" ← [OK] No verbose error detected (body: {r.text[:80]})")

    return vulnerable


def test_openapi_spec_exposed():
    """
    API8 Test: Is the OpenAPI/Swagger spec publicly accessible without auth?
    """
    print(f"\n[API8:Misconfig] OpenAPI / Swagger Spec Exposure")

    spec_paths = [
        "/openapi.json",
        "/swagger.json",
        "/api-docs",
        "/api/docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/swagger-ui.html",
        "/swagger-ui",
        "/api/swagger.json",
        "/workshop/openapi.json",
        "/identity/openapi.json",
    ]

    exposed = []
    for path in spec_paths:
        r = requests.get(f"{BASE_URL}{path}", timeout=5)
        if r.status_code == 200 and len(r.text) > 100:
            is_spec = any(kw in r.text.lower() for kw in
                          ["openapi", "swagger", "paths", "components", "info"])
            print(f"  {path} → HTTP {r.status_code} ({'SPEC FOUND' if is_spec else 'content returned'})")
            if is_spec:
                exposed.append(path)
        else:
            print(f"  {path} → HTTP {r.status_code}")

    if exposed:
        print(f"\n  [VULNERABLE] API spec exposed without authentication at: {exposed}")
        return True
    else:
        print(f"\n  [PROTECTED] No unauthenticated API spec found")
        return False


def test_http_only_no_https():
    """
    API8 Test: Is the API running over plain HTTP (no TLS)?
    """
    print(f"\n[API8:Misconfig] Plain HTTP (No TLS) Check")
    r = requests.get(f"{BASE_URL}/", allow_redirects=False)
    print(f"  Base URL: {BASE_URL}")
    print(f"  Response: HTTP {r.status_code}")

    if BASE_URL.startswith("http://"):
        print(f"  [VULNERABLE] API served over plain HTTP — all traffic unencrypted!")
        hsts = r.headers.get("Strict-Transport-Security")
        if not hsts:
            print(f"  [VULNERABLE] No HSTS header to force HTTPS upgrade")
        return True
    else:
        print(f"  [PROTECTED] HTTPS in use")
        return False


def test_default_credentials():
    """
    API8 Test: Are default/weak admin credentials accepted?
    (crAPI docker-compose ships with admin@example.com / Admin!123)
    """
    print(f"\n[API8:Misconfig] Default Credentials Check")

    default_creds = [
        ("admin@example.com", "Admin1234"),
        ("admin@example.com", "Admin!123"),
        ("admin@crapi.com",   "admin"),
        ("test@test.com",     "test"),
    ]

    for email, password in default_creds:
        r = requests.post(f"{BASE_URL}/identity/api/auth/login",
                          json={"email": email, "password": password})
        print(f"  {email} / {password} → HTTP {r.status_code}", end="")
        if r.status_code == 200:
            token = r.json().get("token", "")
            print(f" ← [VULNERABLE] Default credentials work! Token: {token[:30]}...")
            return True
        else:
            print()

    print(f"  [PROTECTED] None of the default credential sets worked")
    return False


def main():
    print("=" * 60)
    print("  crAPI - API8: Security Misconfiguration")
    print("=" * 60)
    print(f"\nTarget: {BASE_URL}")

    results = []
    results.append(("CORS Misconfiguration",        test_cors_misconfiguration()))
    results.append(("Missing Security Headers",      test_security_headers()))
    results.append(("Verbose Error Messages",        test_verbose_error_messages()))
    results.append(("OpenAPI Spec Exposed",          test_openapi_spec_exposed()))
    results.append(("Plain HTTP (No TLS)",           test_http_only_no_https()))
    results.append(("Default Credentials",           test_default_credentials()))

    print("\n" + "=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    for name, vuln in results:
        status = "VULNERABLE ⚠️ " if vuln else "PROTECTED  ✅"
        print(f"  {status}  {name}")
    print()


if __name__ == "__main__":
    main()
