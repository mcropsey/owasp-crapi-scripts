# crAPI × OWASP API Security Top 10:2023 — Test Suite

A complete lab toolkit for demonstrating and validating all ten OWASP API Security
Top 10:2023 vulnerabilities against a live crAPI instance, with a baseline traffic
generator to train your API security tooling before running exploits.

---

## Recommended Workflow

```
Step 1: Setup Users       → python setup_users.py
Step 2: Generate Baseline → python baseline_traffic.py --minutes 20
Step 3: Run OWASP Exploits → python run_all_tests.py
```

Follow these steps in order. Skipping Step 2 means your API security tool won't
have a learned baseline, so anomaly detection results will be unreliable.

---

## Step 1 — Create Test Users

Before running anything else, register the two test accounts crAPI needs:

```bash
python setup_users.py
```

This script:
- Registers **Alice Attacker** (`user1@example.com`) and **Bob Victim** (`user2@example.com`)
- If accounts already exist with different passwords, it auto-resets via the
  forgot-password + OTP flow, pulling the OTP from MailHog automatically
- Falls back to prompting you for the OTP manually if MailHog isn't reachable

**MailHog** (email inbox for OTP codes): `http://crapi.cropseyit.com:8025`

Expected output when successful:
```
✅  user1@example.com / User1Pass!1
✅  user2@example.com / User2Pass!2
Both users ready — run: python run_all_tests.py
```

---

## Step 2 — Generate Baseline Traffic

Run realistic, normal user activity across all crAPI APIs so your security tool
can learn what legitimate behavior looks like before you throw exploits at it.

```bash
# Run for 20 minutes (recommended minimum)
python baseline_traffic.py --minutes 20

# Run for 30 minutes for a richer baseline
python baseline_traffic.py --minutes 30

# Run a fixed number of cycles
python baseline_traffic.py --cycles 50

# Run indefinitely until Ctrl+C
python baseline_traffic.py
```

### Flags

| Flag | Description |
|---|---|
| `--minutes N` | Stop automatically after N minutes. Ideal for cron jobs — e.g. `--minutes 45` in an hourly cron leaves 15 min rest between runs. |
| `--cycles N` | Stop after N full activity cycles. Each cycle is ~10–20 requests and takes roughly 30–60 seconds depending on server response times. |
| *(no flags)* | Runs indefinitely until you press Ctrl+C. |

### What baseline traffic covers

Both users alternate realistic activity across every crAPI API surface:

| API Area | Actions Simulated |
|---|---|
| Identity / Auth | Login, dashboard view, profile updates, token refresh |
| Vehicles | Add vehicle, view vehicle list, check GPS location, request location refresh |
| Workshop / Shop | Browse products, place orders, return orders |
| Mechanic | Submit service requests via contact_mechanic, view mechanic reports |
| Community | Browse recent posts, create new posts with varied content |
| Coupons | Occasional coupon validation attempts |

Traffic is randomized — not every action runs every cycle — to simulate natural
human behavior patterns rather than scripted polling.

**Recommended baseline duration:** 15–30 minutes minimum before running exploits.
Longer is better. For a demo environment, 20 minutes gives most tools enough
signal to distinguish normal from anomalous.

---

## Step 3 — Run OWASP Exploit Tests

After baseline is established, run the full test suite:

```bash
# Run all 10 tests
python run_all_tests.py

# Run a single test
python api1_bola.py

# Skip the resource consumption stress test (API4)
python run_all_tests.py --skip 4

# Run only specific tests
python run_all_tests.py --only 1 2 9
```

---

## Configuration

All scripts pull from a single config file — edit only this:

**`crapi_config.py`**
```python
BASE_URL       = "https://crapi.cropseyit.com"
USER1_EMAIL    = "user1@example.com"
USER1_PASSWORD = "User1Pass!1"
USER2_EMAIL    = "user2@example.com"
USER2_PASSWORD = "User2Pass!2"
ADMIN_EMAIL    = "admin@example.com"
ADMIN_PASSWORD = "Admin!123"
```

---

## Test Scripts — OWASP API Top 10:2023

| Script | Category | Key crAPI Vulnerability Demonstrated |
|---|---|---|
| `api1_bola.py` | API1: BOLA | Access other user's vehicle location via UUID enumeration |
| `api2_broken_auth.py` | API2: Broken Authentication | OTP brute-force on v2 endpoint; JWT alg=none; no login lockout |
| `api3_broken_object_property.py` | API3: Mass Assignment | Inject `role`/`isAdmin` fields; vehicle PII over-exposure |
| `api4_resource_consumption.py` | API4: Resource Consumption | Unlimited coupon redemption; no rate limiting; large payload |
| `api5_bfla.py` | API5: BFLA | Regular user accessing admin/mechanic function endpoints |
| `api6_business_flow.py` | API6: Business Flow Abuse | Race condition orders; coupon replay; mechanic SSRF logic abuse |
| `api7_ssrf.py` | API7: SSRF | `mechanic_api` URL param triggers server-side fetch |
| `api8_security_misconfig.py` | API8: Security Misconfiguration | Missing headers; CORS; verbose errors; default creds; plain HTTP |
| `api9_inventory_management.py` | API9: Inventory Management | v2 OTP endpoint active without rate limit; shadow endpoint fuzzing |
| `api10_unsafe_consumption.py` | API10: Unsafe Consumption | Stored XSS via mechanic callback; injection in community posts |

---

## Prerequisites

- **Python 3.7+** with `pip install requests`
- **crAPI** running and accessible at `https://crapi.cropseyit.com`
- **MailHog** accessible at `http://crapi.cropseyit.com:8025` (for OTP emails)
- At least one **vehicle added** per user account (needed for API1, API7, API10)
  — add via the crAPI UI after running `setup_users.py`

---

## Akamai API Security Detection Mapping

| OWASP Category | Akamai Detection Capability |
|---|---|
| API1: BOLA | Behavioral anomaly — user accessing another user's object IDs |
| API2: Broken Auth | Auth anomaly detection; token replay; brute-force pattern detection |
| API3: Mass Assignment | Request payload inspection; schema deviation detection |
| API4: Resource Consumption | Rate limiting; traffic spike detection |
| API5: BFLA | Endpoint access pattern analysis; role-function mapping |
| API6: Business Flow | Sequence analysis; velocity-based business logic checks |
| API7: SSRF | Outbound request inspection; internal-target access detection |
| API8: Misconfiguration | API posture management; spec compliance; header policy |
| API9: Inventory Management | API discovery; shadow/zombie API detection; version tracking |
| API10: Unsafe Consumption | Third-party API traffic inspection; response anomaly detection |

---

> **Warning:** These scripts are for authorized lab use only against crAPI,
> an intentionally vulnerable application. Never run against production systems.
