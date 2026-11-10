"""
Creates SYNTHETIC login + account-activity data for an online banking / e-wallet app.
200 customers, 14 days, with hidden account-takeover (ATO) cases and some
"looks scary but is fine" cases (real travel, new phone).

You don't need to run this — data/ is already included.
"""
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

random.seed(11)
MYT = timezone(timedelta(hours=8))
START = datetime(2026, 10, 20, tzinfo=MYT)
DAYS = 14
OUT = Path(__file__).parent / "data"

CITIES = {   # city: (country, lat, lon)
    "Kuala Lumpur": ("MY", 3.139, 101.687), "Petaling Jaya": ("MY", 3.107, 101.607),
    "Cyberjaya": ("MY", 2.922, 101.650), "Penang": ("MY", 5.414, 100.329),
    "Johor Bahru": ("MY", 1.492, 103.741), "Ipoh": ("MY", 4.597, 101.090),
    "Kota Kinabalu": ("MY", 5.980, 116.073), "Kuching": ("MY", 1.553, 110.359),
    "Singapore": ("SG", 1.352, 103.820), "Tokyo": ("JP", 35.676, 139.650),
    "Amsterdam": ("NL", 52.367, 4.904), "Ho Chi Minh City": ("VN", 10.823, 106.630),
    "Lagos": ("NG", 6.524, 3.379),
}
HOME_CITIES = [c for c, v in CITIES.items() if v[0] == "MY"]
logins, events = [], []
ip_counter = iter(range(10, 250))


def ip_for(city):
    """Fake IPs from documentation ranges, stable-ish per city."""
    base = {"MY": "203.0.113", "SG": "198.51.100", "JP": "198.51.100",
            "NL": "192.0.2", "VN": "192.0.2", "NG": "192.0.2"}[CITIES[city][0]]
    return f"{base}.{sum(map(ord, city)) % 200 + 10}"


def login(t, cust, city, device, result="SUCCESS", mfa="PASS"):
    country, lat, lon = CITIES[city]
    logins.append({"ts": t, "customer_id": cust, "ip": ip_for(city), "country": country,
                   "city": city, "lat": lat, "lon": lon, "device_id": device,
                   "result": result, "mfa": mfa})


def event(t, cust, etype, detail="", amount=0.0):
    events.append({"ts": t, "customer_id": cust, "event_type": etype,
                   "detail": detail, "amount_myr": round(amount, 2)})


def day(d, h=0, m=0):
    return START + timedelta(days=d, hours=h, minutes=m)


# ---------- Normal customers ----------
customers = [f"C{1000 + i}" for i in range(200)]
profile = {}
FIXED_HOME = {"C1100": "Johor Bahru", "C1150": "Kuala Lumpur"}   # for the travel examples
for c in customers:
    home = FIXED_HOME.get(c) or random.choice(HOME_CITIES)
    devices = [f"D-{c}-{k}" for k in range(random.choice([1, 1, 2]))]
    profile[c] = (home, devices)
    for d in range(DAYS):
        for _ in range(random.choice([0, 1, 1, 2, 3])):
            t = day(d, random.randint(7, 22), random.randint(0, 59))
            if random.random() < 0.04:                     # typo'd password, then success
                login(t, c, home, devices[0], "FAIL", "NONE")
                t += timedelta(minutes=1)
            login(t, c, home, random.choice(devices))
            if random.random() < 0.25:
                event(t + timedelta(minutes=3), c, "TRANSFER", "existing payee",
                      random.uniform(20, 900))

# ---------- Looks risky, but is legitimate ----------
# C1100: weekend in Singapore from Johor Bahru (short distance, plenty of time)
login(day(5, 9), "C1100", "Johor Bahru", profile["C1100"][1][0])
login(day(5, 15), "C1100", "Singapore", profile["C1100"][1][0])
# C1150: flies KL -> Tokyo; 9 h between logins = possible by plane
login(day(8, 6, 30), "C1150", "Kuala Lumpur", profile["C1150"][1][0])
login(day(8, 15, 40), "C1150", "Tokyo", profile["C1150"][1][0])
# C1120: buys a new phone, logs in from home, MFA passes, nothing else changes
login(day(9, 20), "C1120", profile["C1120"][0], "D-C1120-NEWPHONE")

# ---------- Case 1: full account takeover, money stolen (C1042) ----------
home, devs = profile["C1042"]
login(day(10, 8, 55), "C1042", home, devs[0])                        # real owner
for k in range(4):                                                   # attacker guesses OTP
    login(day(10, 10, 31) + timedelta(seconds=40 * k), "C1042", "Amsterdam", "D-ATK-77", "FAIL", "NONE")
login(day(10, 10, 34), "C1042", "Amsterdam", "D-ATK-77", "SUCCESS", "PASS")
event(day(10, 10, 37), "C1042", "EMAIL_CHANGE", "new: c1042.secure@mail.test")
event(day(10, 10, 39), "C1042", "PHONE_CHANGE", "new: +31-xxx")
event(day(10, 10, 44), "C1042", "ADD_PAYEE", "PAYEE-MULE-01")
event(day(10, 10, 47), "C1042", "TRANSFER", "PAYEE-MULE-01", 8500)
event(day(10, 10, 52), "C1042", "TRANSFER", "PAYEE-MULE-01", 4900)

# ---------- Case 2: e-commerce style takeover — new address + big order (C1077) ----------
home, devs = profile["C1077"]
for k in range(3):
    login(day(11, 2, 10) + timedelta(seconds=30 * k), "C1077", "Ho Chi Minh City", "D-ATK-31", "FAIL", "NONE")
event(day(11, 2, 12), "C1077", "PASSWORD_RESET", "via email link")
login(day(11, 2, 14), "C1077", "Ho Chi Minh City", "D-ATK-31")
event(day(11, 2, 18), "C1077", "ADD_ADDRESS", "new shipping address: Kepong")
event(day(11, 2, 21), "C1077", "TRANSFER", "online order: 2 x smartphone", 11200)

# ---------- Case 3: SIM-swap warning sign, stopped before money moved (C1188) ----------
home, devs = profile["C1188"]
event(day(12, 14, 2), "C1188", "PHONE_CHANGE", "new SIM registered")
login(day(12, 14, 20), "C1188", home, "D-ATK-90")
event(day(12, 14, 26), "C1188", "ADD_PAYEE", "PAYEE-X-12")

# ---------- Case 4: one mule account receiving from several victims ----------
for i, c in enumerate(["C1031", "C1064", "C1133", "C1171"]):
    home, devs = profile[c]
    t = day(12 + i // 2, 19 + i, 5)
    login(t, c, "Lagos", f"D-ATK-5{i}")
    event(t + timedelta(minutes=6), c, "ADD_PAYEE", "PAYEE-MULE-01")
    event(t + timedelta(minutes=9), c, "TRANSFER", "PAYEE-MULE-01", random.uniform(1500, 4000))

OUT.mkdir(exist_ok=True)
for name, rows in [("logins", logins), ("account_events", events)]:
    df = pd.DataFrame(rows).sort_values("ts")
    df["ts"] = df["ts"].map(lambda t: t.strftime("%Y-%m-%d %H:%M:%S"))
    df.to_csv(OUT / f"{name}.csv", index=False)
    print(f"Wrote {len(df):,} rows to data/{name}.csv")
