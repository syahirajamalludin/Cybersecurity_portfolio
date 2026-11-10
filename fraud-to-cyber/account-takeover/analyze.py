"""
Account Takeover (ATO) detection — fraud analytics meets cybersecurity.

Usage:  python analyze.py
Input:  data/logins.csv, data/account_events.csv
Rules:  detections.sql (7 SQL rules) + impossible travel (Python)
Output: risk-scored list of accounts + charts in img/

Like a fraud rule engine: each rule adds points, the total decides the priority.
"""
import math
import re
import sqlite3
from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd

HERE = Path(__file__).parent
MAX_SPEED_KMH = 900            # faster than a passenger plane = impossible
MIN_DISTANCE_KM = 500          # ignore small jumps (IP geolocation is fuzzy)
POINTS = {                     # how much each signal adds to the risk score
    "impossible_travel": 40, "money_after_new_device": 30, "shared_payee": 30,
    "sensitive_after_new_device": 25, "sim_swap": 25,
    "new_device": 15, "new_country": 15, "failed_then_success": 10,
}
LEVELS = [(100, "🔴 CRITICAL"), (60, "🟠 HIGH"), (30, "🟡 MEDIUM")]

pd.set_option("display.width", 160)
pd.set_option("display.max_columns", 12)

# ---------- 1. Load into an in-memory SQL database ----------
logins = pd.read_csv(HERE / "data" / "logins.csv", parse_dates=["ts"])
events = pd.read_csv(HERE / "data" / "account_events.csv", parse_dates=["ts"])
db = sqlite3.connect(":memory:")
for name, df in [("logins", logins), ("account_events", events)]:
    df.assign(ts=df.ts.dt.strftime("%Y-%m-%d %H:%M:%S")).to_sql(name, db, index=False)
print(f"Logins: {len(logins):,} | Account events: {len(events):,} | "
      f"Customers: {logins.customer_id.nunique()} | "
      f"{logins.ts.min():%d %b} – {logins.ts.max():%d %b %Y}\n")

# ---------- 2. Run every SQL rule ----------
sql_text = (HERE / "detections.sql").read_text()
results = {}
for block in re.split(r"^-- name: ", sql_text, flags=re.M)[1:]:
    name, body = block.split("\n", 1)
    results[name.strip()] = pd.read_sql_query(body, db)

# ---------- 3. Impossible travel (needs maths, so done in Python) ----------
def km_between(lat1, lon1, lat2, lon2):
    """Great-circle distance (haversine formula)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(a))


ok = logins[logins.result == "SUCCESS"].sort_values(["customer_id", "ts"])
prev = ok.groupby("customer_id").shift(1)
travel = ok.assign(prev_city=prev.city, prev_ts=prev.ts,
                   km=[km_between(a, b, c, d) if pd.notna(a) else 0
                       for a, b, c, d in zip(prev.lat, prev.lon, ok.lat, ok.lon)])
travel["hours"] = (travel.ts - travel.prev_ts).dt.total_seconds() / 3600
travel["kmh"] = travel.km / travel.hours.clip(lower=1 / 60)
impossible = travel[(travel.km >= MIN_DISTANCE_KM) & (travel.kmh > MAX_SPEED_KMH)]
results["impossible_travel"] = impossible[
    ["customer_id", "prev_city", "city", "prev_ts", "ts", "km", "hours", "kmh"]].round(
    {"km": 0, "hours": 1, "kmh": 0})
possible_trips = travel[(travel.km >= MIN_DISTANCE_KM) & (travel.kmh <= MAX_SPEED_KMH)]

# ---------- 4. Show each rule ----------
for name in POINTS:
    r = results[name]
    print(f"── {name} (+{POINTS[name]} pts) — {len(r)} hit(s) " + "─" * 20)
    print(r.head(12).to_string(index=False) if len(r) else "   none")
    print()

# ---------- 5. Risk score per customer ----------
hits = {}
for name, r in results.items():
    if name == "shared_payee":   # one row per payee -> credit every victim
        custs = {c for row in r.customers for c in row.split(",")}
    else:
        custs = set(r.customer_id)
    for c in custs:
        hits.setdefault(c, []).append(name)

score = pd.DataFrame([{"customer_id": c, "score": sum(POINTS[s] for s in sig),
                       "signals": ", ".join(sorted(sig, key=lambda s: -POINTS[s]))}
                      for c, sig in hits.items()]).sort_values("score", ascending=False)
score["priority"] = score.score.map(
    lambda s: next((label for limit, label in LEVELS if s >= limit), "⚪ no alert"))
money = results["money_after_new_device"].groupby("customer_id").total_myr.sum()
score["money_out_myr"] = score.customer_id.map(money).fillna(0)

print("=" * 90 + "\nRISK-SCORED ALERT QUEUE (highest first)\n" + "=" * 90)
print(score[score.score >= 30].to_string(index=False))
print(f"\nLow-risk signals that did NOT become alerts: "
      f"{(score.score < 30).sum()} customers (e.g. new phone only, one foreign login)")
alerted = set(score[score.score >= 30].customer_id)
print("Long trips judged POSSIBLE for customers with no alert (real travel):")
print(possible_trips[~possible_trips.customer_id.isin(alerted)]
      [["customer_id", "prev_city", "city", "km", "hours", "kmh"]].round(0).to_string(index=False))
urgent = score[score.score >= 60]
print(f"\nMoney out in CRITICAL/HIGH alerts: RM {urgent.money_out_myr.sum():,.2f} "
      f"across {len(urgent)} accounts")

# ---------- 6. Charts ----------
(HERE / "img").mkdir(exist_ok=True)
plt.rcParams.update({"axes.spines.top": False, "axes.spines.right": False})
RED, GREY, BLUE = "#d1453b", "#8a8f98", "#4a7bb7"

# 6a. Timeline of the worst case
worst = score.iloc[0].customer_id
lg = logins[logins.customer_id == worst]
ev = events[events.customer_id == worst]
t0 = lg[lg.device_id.str.startswith("D-ATK")].ts.min()     # attacker's first attempt
start, end = t0 - pd.Timedelta("2h"), t0 + pd.Timedelta("1h")
lg, ev = lg[lg.ts.between(start, end)], ev[ev.ts.between(start, end)]
fig, ax = plt.subplots(figsize=(10, 4.2))
rows = []
for r in lg.itertuples():
    ok_ = r.result == "SUCCESS"
    rows.append((r.ts, f"Login {'OK' if ok_ else 'FAIL'} · {r.city}",
                 RED if r.device_id.startswith("D-ATK") else GREY))
for r in ev.itertuples():
    label = r.event_type.replace("_", " ").title()
    if r.amount_myr:
        label += f" · RM {r.amount_myr:,.0f}"
    rows.append((r.ts, label, RED))
rows.sort()
for i, (t, label, colour) in enumerate(rows):
    ax.scatter(t, i, color=colour, s=40, zorder=3)
    ax.text(t, i, "  " + label, va="center", fontsize=8.5)
ax.set_yticks([])
ax.invert_yaxis()
ax.spines["left"].set_visible(False)
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.set_xlim(rows[0][0] - pd.Timedelta("5min"), rows[-1][0] + pd.Timedelta("40min"))
ax.set_title(f"{worst} on {t0:%d %b %Y}: owner logs in, then the attacker takes over (red)")
fig.tight_layout()
fig.savefig(HERE / "img" / "ato_timeline.png", dpi=150)

# 6b. Alert queue
alerts = score[score.score >= 30].iloc[::-1]
colours = [RED if s >= 100 else "#e08a2c" if s >= 60 else "#d9b23a" for s in alerts.score]
fig, ax = plt.subplots(figsize=(8, 0.45 * len(alerts) + 1.2))
ax.barh(alerts.customer_id, alerts.score, color=colours)
for y, (s, m) in enumerate(zip(alerts.score, alerts.money_out_myr)):
    ax.text(s + 2, y, f"{s} pts" + (f" · RM {m:,.0f} out" if m else ""), va="center", fontsize=9)
for limit, _ in LEVELS:
    ax.axvline(limit, color=GREY, lw=0.8, ls="--")
ax.set_xlim(0, alerts.score.max() * 1.45)
ax.set_xlabel("Risk score  (dashed lines: 30 medium · 60 high · 100 critical)")
ax.set_title("Alert queue — what an analyst would work first")
fig.tight_layout()
fig.savefig(HERE / "img" / "alert_queue.png", dpi=150)

# 6c. Mule network
sp = results["shared_payee"]
if len(sp):
    row = sp.iloc[0]
    victims = row.customers.split(",")
    fig, ax = plt.subplots(figsize=(6, 4))
    for i, v in enumerate(victims):
        angle = math.pi * (0.15 + 0.7 * i / max(len(victims) - 1, 1))
        x, y = math.cos(angle) * 2, math.sin(angle) * 2
        amt = events[(events.customer_id == v) & (events.detail == row.payee)].amount_myr.sum()
        ax.annotate("", xy=(0, 0), xytext=(x, y),
                    arrowprops=dict(arrowstyle="->", color=RED, lw=1.5))
        ax.scatter(x, y, s=900, color=BLUE, zorder=3)
        ax.text(x, y, v, color="white", ha="center", va="center", fontsize=8, zorder=4)
        ax.text(x / 2, y / 2, f"RM {amt:,.0f}", fontsize=8, ha="center",
                bbox=dict(fc="white", ec="none", pad=1))
    ax.scatter(0, 0, s=2200, color=RED, zorder=3)
    ax.text(0, 0, row.payee.replace("PAYEE-", ""), color="white", ha="center",
            va="center", fontsize=9, weight="bold", zorder=4)
    ax.set_xlim(-2.6, 2.6)
    ax.set_ylim(-0.6, 2.5)
    ax.axis("off")
    ax.set_title(f"{len(victims)} victims → 1 mule account ({row.payee})")
    fig.tight_layout()
    fig.savefig(HERE / "img" / "mule_network.png", dpi=150)

print("\nCharts saved to img/")
