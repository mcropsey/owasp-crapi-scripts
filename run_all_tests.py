#!/usr/bin/env python3
"""
crAPI OWASP API Security Top 10:2023 - Master Test Runner
Runs all 10 vulnerability test scripts against your crAPI Docker lab.

Usage:
    python run_all_tests.py [--host HOST] [--port PORT]

Default target: http://localhost:8888
"""

import subprocess
import sys
import argparse
import time
import os

SCRIPTS = [
    ("API1:  Broken Object Level Authorization (BOLA)",          "api1_bola.py"),
    ("API2:  Broken Authentication",                              "api2_broken_auth.py"),
    ("API3:  Broken Object Property Level Authorization",         "api3_broken_object_property.py"),
    ("API4:  Unrestricted Resource Consumption",                  "api4_resource_consumption.py"),
    ("API5:  Broken Function Level Authorization (BFLA)",         "api5_bfla.py"),
    ("API6:  Unrestricted Access to Sensitive Business Flows",    "api6_business_flow.py"),
    ("API7:  Server Side Request Forgery (SSRF)",                 "api7_ssrf.py"),
    ("API8:  Security Misconfiguration",                          "api8_security_misconfig.py"),
    ("API9:  Improper Inventory Management",                      "api9_inventory_management.py"),
    ("API10: Unsafe Consumption of APIs",                         "api10_unsafe_consumption.py"),
]

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║      crAPI × OWASP API Security Top 10:2023 Test Suite      ║
║         Target: https://crapi.cropseyit.com                  ║
╚══════════════════════════════════════════════════════════════╝
"""


def run_script(script_path, label, index, total):
    print(f"\n{'='*64}")
    print(f"  [{index}/{total}] Running: {label}")
    print(f"  Script: {script_path}")
    print(f"{'='*64}\n")

    start = time.time()
    result = subprocess.run(
        [sys.executable, script_path],
        capture_output=False,
        text=True
    )
    elapsed = time.time() - start

    print(f"\n  ↳ Completed in {elapsed:.1f}s (exit code: {result.returncode})")
    return result.returncode


def main():
    parser = argparse.ArgumentParser(description="Run all crAPI OWASP API Top 10 tests")
    parser.add_argument("--skip", nargs="+", type=int, metavar="N",
                        help="Skip specific API tests by number (e.g., --skip 4 7)")
    parser.add_argument("--only", nargs="+", type=int, metavar="N",
                        help="Run only specific API tests (e.g., --only 1 2 9)")
    args = parser.parse_args()

    print(BANNER)

    script_dir = os.path.dirname(os.path.abspath(__file__))
    total = len(SCRIPTS)
    results = []

    for i, (label, filename) in enumerate(SCRIPTS, start=1):
        api_num = i

        if args.only and api_num not in args.only:
            print(f"  [SKIP] API{api_num}: {filename} (not in --only list)")
            continue
        if args.skip and api_num in args.skip:
            print(f"  [SKIP] API{api_num}: {filename} (in --skip list)")
            continue

        script_path = os.path.join(script_dir, filename)
        if not os.path.exists(script_path):
            print(f"  [ERROR] Script not found: {script_path}")
            results.append((label, "MISSING"))
            continue

        exit_code = run_script(script_path, label, i, total)
        results.append((label, "OK" if exit_code == 0 else f"EXIT {exit_code}"))

        # Pause between tests to avoid hammering the server
        time.sleep(1)

    print(f"\n{'='*64}")
    print(f"  MASTER SUMMARY - All Tests Complete")
    print(f"{'='*64}")
    for label, status in results:
        icon = "✅" if status == "OK" else "❌"
        print(f"  {icon} {label}")
    print()
    print("  Review individual test output above for VULNERABLE/PROTECTED results.")
    print("  Remember: this is an intentionally vulnerable app for training only.")
    print()


if __name__ == "__main__":
    main()
