#!/usr/bin/env python3
"""
crAPI Baseline Traffic Generator
Simulates realistic, normal user behavior across all crAPI endpoints
to establish a clean traffic baseline for your API security tool.

Run this for 15-30 minutes BEFORE running the OWASP exploit scripts.

Usage:
    python baseline_traffic.py              # runs until Ctrl+C
    python baseline_traffic.py --minutes 20 # runs for 20 minutes
    python baseline_traffic.py --cycles 50  # runs 50 full cycles then stops
"""

import requests
import time
import random
import argparse
import sys
import json
from datetime import datetime

from crapi_config import (
    BASE_URL,
    USER1_EMAIL, USER1_PASSWORD,
    USER2_EMAIL, USER2_PASSWORD,
)

# ── Tunables ──────────────────────────────────────────────────────────────────
MIN_DELAY = 0.5   # seconds between requests (simulates human pace)
MAX_DELAY = 2.5
# ──────────────────────────────────────────────────────────────────────────────

session1 = requests.Session()
session2 = requests.Session()

STATS = {"requests": 0, "ok": 0, "errors": 0, "cycles": 0}


# ── Helpers ───────────────────────────────────────────────────────────────────

def pause():
    time.sleep(random.uniform(MIN_DELAY, MAX_DELAY))


def log(label, method, path, status):
    STATS["requests"] += 1
    if status < 400:
        STATS["ok"] += 1
        icon = "✅"
    else:
        STATS["errors"] += 1
        icon = "⚠️ "
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"  {ts} {icon} [{label}] {method} {path} → {status}")


def get(session, label, path, **kwargs):
    r = session.get(f"{BASE_URL}{path}", timeout=10, **kwargs)
    log(label, "GET ", path, r.status_code)
    pause()
    return r


def post(session, label, path, body, **kwargs):
    r = session.post(f"{BASE_URL}{path}", json=body, timeout=10, **kwargs)
    log(label, "POST", path, r.status_code)
    pause()
    return r


def put(session, label, path, body, **kwargs):
    r = session.put(f"{BASE_URL}{path}", json=body, timeout=10, **kwargs)
    log(label, "PUT ", path, r.status_code)
    pause()
    return r


# ── Auth ──────────────────────────────────────────────────────────────────────

def login(session, email, password, label):
    r = session.post(f"{BASE_URL}/identity/api/auth/login",
                     json={"email": email, "password": password}, timeout=10)
    if r.status_code == 200:
        token = r.json().get("token")
        session.headers.update({"Authorization": f"Bearer {token}"})
        log(label, "POST", "/identity/api/auth/login", r.status_code)
        pause()
        return token
    else:
        print(f"  [ERROR] Login failed for {email} (HTTP {r.status_code})")
        print(f"          Run setup_users.py first to fix credentials.")
        sys.exit(1)


# ── crAPI workflow actions ────────────────────────────────────────────────────

def action_view_dashboard(session, label):
    get(session, label, "/identity/api/v2/user/dashboard")


def action_view_vehicles(session, label):
    r = get(session, label, "/identity/api/v2/vehicle/vehicles")
    if r.status_code == 200 and r.json():
        return r.json()
    return []


def action_view_vehicle_location(session, label, vehicles):
    if not vehicles:
        return
    v = random.choice(vehicles)
    uuid = v.get("uuid")
    if uuid:
        get(session, label, f"/identity/api/v2/vehicle/{uuid}/location")


def action_refresh_vehicle_location(session, label, vehicles):
    """Simulate GPS refresh — POST to update location."""
    if not vehicles:
        return
    v = random.choice(vehicles)
    uuid = v.get("uuid")
    if uuid:
        post(session, label, f"/identity/api/v2/vehicle/{uuid}/resend_email", {})


def action_view_community_posts(session, label):
    get(session, label, "/community/api/v2/community/posts/recent")


def action_create_community_post(session, label, user_num):
    topics = [
        ("Loving my new car!", "Just picked it up — handles great on the highway."),
        ("Fuel economy tips?", "Anyone else getting better mileage after the last service?"),
        ("Road trip this weekend", "Heading up north — anyone know good rest stops on I-43?"),
        ("Strange noise at startup", "Slight tick when cold — normal or should I get it checked?"),
        ("Car wash recommendations", "Looking for a touchless wash near Green Bay, any suggestions?"),
        ("Winter tire question", "Time to swap to snow tires — what are you all running?"),
        ("Oil change interval", "Dealer says 5k miles, manual says 7.5k — what do you do?"),
        ("New infotainment update", "Just got the OTA update — nav feels much snappier now."),
    ]
    title, body = random.choice(topics)
    title = f"[User{user_num}] {title}"
    post(session, label, "/community/api/v2/community/posts",
         {"title": title, "body": body})


def action_view_shop(session, label):
    return get(session, label, "/workshop/api/shop/products")


def action_place_order(session, label, products):
    if not products:
        return None
    p = random.choice(products)
    r = post(session, label, "/workshop/api/shop/orders",
             {"product_id": p.get("id"), "quantity": 1})
    if r.status_code in (200, 201):
        try:
            return r.json().get("id") or r.json().get("order_id")
        except Exception:
            pass
    return None


def action_view_orders(session, label):
    get(session, label, "/workshop/api/shop/orders/all")


def action_return_order(session, label, order_id):
    if order_id:
        put(session, label, f"/workshop/api/shop/orders/{order_id}/return_order", {})


def action_contact_mechanic(session, label, vehicles):
    if not vehicles:
        return
    v = random.choice(vehicles)
    vin = v.get("vin", "UNKNOWN")
    problems = [
        "Routine oil change service request",
        "Tire rotation and balance check",
        "Brake inspection needed",
        "Check engine light came on briefly",
        "AC not cooling as well as it used to",
        "Windshield wiper fluid low, please top off",
    ]
    post(session, label, "/workshop/api/mechanic/contact_mechanic", {
        "mechanic_api": f"{BASE_URL}/workshop/api/mechanic/",
        "problem_details": random.choice(problems),
        "vin": vin,
        "mechanic_code": "TRAC_JHJ",
        "repeat_request_if_failed": False,
        "number_of_repeats": 1,
    })


def action_view_mechanic_reports(session, label):
    # Browse a few report IDs that belong to this user
    for report_id in [1, 2]:
        get(session, label, f"/workshop/api/mechanic/mechanic_report?report_id={report_id}")


def action_update_profile(session, label, user_num):
    names = ["Alice Attacker", "A. Attacker", "Alice A."] if user_num == 1 \
            else ["Bob Victim", "B. Victim", "Robert Victim"]
    put(session, label, "/identity/api/v2/user/dashboard",
        {"name": random.choice(names), "number": f"555100000{user_num}"})


def action_validate_coupon(session, label):
    # Only try once per cycle, with a valid-ish code (may 404 if not seeded)
    coupons = ["TRAC075", "CRAPI100", "OWASP50"]
    post(session, label, "/community/api/v2/coupon/validate-coupon",
         {"coupon_code": random.choice(coupons)})


def action_add_vehicle(session, label, existing_vehicles):
    """Only add a vehicle if the user has none yet."""
    if existing_vehicles:
        return existing_vehicles
    # Try to add a sample vehicle — VIN must be real format or crAPI rejects
    # Use the seeded test VINs from crAPI's default data
    sample_vins = [
        ("5GZCZ43D13S812715", "1234"),
        ("1GNALDEK9FZ108495", "4321"),
    ]
    vin, pin = random.choice(sample_vins)
    r = post(session, label, "/identity/api/v2/vehicle/add_vehicle",
             {"vin": vin, "pincode": pin})
    if r.status_code in (200, 201):
        return action_view_vehicles(session, label)
    return existing_vehicles


# ── Main cycle ────────────────────────────────────────────────────────────────

def run_user_cycle(session, label, user_num, vehicles, products):
    """One realistic 'session' of user activity — picks a random mix of actions."""

    # Always-run: dashboard + community feed
    action_view_dashboard(session, label)
    action_view_community_posts(session, label)

    # Vehicle activity
    vehicles = action_view_vehicles(session, label) or vehicles
    if not vehicles:
        vehicles = action_add_vehicle(session, label, vehicles)

    if random.random() > 0.3:
        action_view_vehicle_location(session, label, vehicles)

    # Shop activity
    r = action_view_shop(session, label)
    if r.status_code == 200:
        try:
            products = r.json().get("products", products)
        except Exception:
            pass

    if random.random() > 0.6:
        order_id = action_place_order(session, label, products)
        if order_id and random.random() > 0.7:
            time.sleep(1)
            action_return_order(session, label, order_id)

    if random.random() > 0.5:
        action_view_orders(session, label)

    # Community post
    if random.random() > 0.5:
        action_create_community_post(session, label, user_num)

    # Mechanic request
    if random.random() > 0.6:
        action_contact_mechanic(session, label, vehicles)

    if random.random() > 0.7:
        action_view_mechanic_reports(session, label)

    # Profile update (occasional)
    if random.random() > 0.8:
        action_update_profile(session, label, user_num)

    # Coupon check (occasional)
    if random.random() > 0.85:
        action_validate_coupon(session, label)

    return vehicles, products


def print_stats(start_time):
    elapsed = time.time() - start_time
    mins = int(elapsed // 60)
    secs = int(elapsed % 60)
    print(f"\n  ── Stats: {STATS['cycles']} cycles | "
          f"{STATS['requests']} requests | "
          f"{STATS['ok']} OK | "
          f"{STATS['errors']} errors | "
          f"Elapsed: {mins}m {secs}s ──\n")


def main():
    parser = argparse.ArgumentParser(description="crAPI baseline traffic generator")
    parser.add_argument("--minutes", type=int, default=0,
                        help="Run for N minutes then stop (default: run until Ctrl+C)")
    parser.add_argument("--cycles",  type=int, default=0,
                        help="Run N full cycles then stop")
    args = parser.parse_args()

    print(f"""
╔══════════════════════════════════════════════════════════════╗
║           crAPI Baseline Traffic Generator                   ║
║         Target: {BASE_URL:<45}║
╚══════════════════════════════════════════════════════════════╝

  Simulating normal user behavior on all crAPI endpoints.
  Run for 15-30 minutes to build a solid baseline.
  Press Ctrl+C to stop.
""")

    # Authenticate both users
    print("  [SETUP] Authenticating users...")
    login(session1, USER1_EMAIL, USER1_PASSWORD, "User1")
    login(session2, USER2_EMAIL, USER2_PASSWORD, "User2")
    print("  [SETUP] Both users authenticated. Starting traffic generation.\n")

    vehicles1, vehicles2 = [], []
    products1, products2 = [], []
    start_time = time.time()
    stop_at = start_time + (args.minutes * 60) if args.minutes else None

    try:
        while True:
            STATS["cycles"] += 1
            cycle = STATS["cycles"]

            print(f"\n{'─'*60}")
            print(f"  Cycle {cycle} — {datetime.now().strftime('%H:%M:%S')}")
            print(f"{'─'*60}")

            # Alternate which user goes first each cycle
            if cycle % 2 == 0:
                vehicles1, products1 = run_user_cycle(session1, "User1", 1, vehicles1, products1)
                vehicles2, products2 = run_user_cycle(session2, "User2", 2, vehicles2, products2)
            else:
                vehicles2, products2 = run_user_cycle(session2, "User2", 2, vehicles2, products2)
                vehicles1, products1 = run_user_cycle(session1, "User1", 1, vehicles1, products1)

            print_stats(start_time)

            # Re-authenticate periodically (token refresh)
            if cycle % 10 == 0:
                print("  [AUTH] Refreshing tokens...")
                login(session1, USER1_EMAIL, USER1_PASSWORD, "User1")
                login(session2, USER2_EMAIL, USER2_PASSWORD, "User2")

            # Check stop conditions
            if args.cycles and cycle >= args.cycles:
                print(f"\n  Reached {args.cycles} cycles — stopping.")
                break
            if stop_at and time.time() >= stop_at:
                print(f"\n  Reached {args.minutes} minutes — stopping.")
                break

            # Inter-cycle pause (simulate user thinking time)
            time.sleep(random.uniform(2, 5))

    except KeyboardInterrupt:
        print("\n\n  [Stopped by user]")

    print_stats(start_time)
    print("  Baseline generation complete.\n")


if __name__ == "__main__":
    main()
