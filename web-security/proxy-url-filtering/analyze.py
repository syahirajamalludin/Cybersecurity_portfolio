"""
Web proxy log analysis — finding threats hidden in one day of Squid logs.

Usage:  python analyze.py
Input:  data/access.log  (format: see `logformat portfolio` in squid/squid.conf)
        squid/blocklists/*.txt  (URL categories — same files the proxy uses)
Output: printed findings + charts in img/

5 checks:
  1. Blocked traffic by category        -> what the policy stopped
  2. Beaconing                          -> malware "phoning home" on a timer
  3. Patient zero                       -> what was downloaded just before beaconing began
  4. Phishing waves                     -> many users clicking the same bad link
  5. Upload spikes                      -> large data leaving the company (after hours)
"""
from pathlib import Path
from urllib.parse import urlsplit

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd

HERE = Path(__file__).parent
BEACON_MIN_HITS = 20        # need at least this many requests to judge regularity
BEACON_MAX_CV = 0.10        # gaps vary < 10% of their average = machine, not human
PATIENT_ZERO_WINDOW = pd.Timedelta("60min")
WORK_START, WORK_END = 8, 20
UPLOAD_ALERT_MB = 500       # after-hours upload volume that needs a look

# ---------- 1. Load ----------
cols = ["epoch", "elapsed_ms", "client_ip", "user", "result", "bytes_up",
        "bytes_down", "method", "url", "mime"]
df = pd.read_csv(HERE / "data" / "access.log", sep=r"\s+", names=cols, engine="python")
df["time"] = (pd.to_datetime(df["epoch"], unit="s", utc=True)
              .dt.tz_convert("Asia/Kuala_Lumpur"))
df["domain"] = df["url"].map(lambda u: urlsplit(u).hostname)
df["action"] = df["result"].str.split("/").str[0].map(
    lambda r: "BLOCKED" if r == "TCP_DENIED" else "ALLOWED")


# ---------- 2. Categorise with the proxy's own blocklists ----------
def load_category(name):
    lines = (HERE / "squid" / "blocklists" / f"{name}.txt").read_text().splitlines()
    return [l.strip().lstrip(".") for l in lines if l.strip() and not l.startswith("#")]


CATEGORIES = {c: load_category(c) for c in
              ["malware", "phishing", "gambling", "social", "filesharing"]}


def categorise(row):
    for cat, domains in CATEGORIES.items():
        if any(row.domain == d or row.domain.endswith("." + d) for d in domains):
            return cat
    if row.action == "BLOCKED" and row.url.lower().endswith((".exe", ".msi", ".scr")):
        return "risky-file"
    return "business/other"


df["category"] = df.apply(categorise, axis=1)

print("=" * 70)
print(f"Requests: {len(df):,} | Users: {df.user.nunique()} | "
      f"Blocked: {(df.action == 'BLOCKED').mean():.1%}")
print(f"Period:   {df.time.min():%d %b %Y %H:%M} – {df.time.max():%H:%M} (MYT)")
print("=" * 70)

blocked = df[df.action == "BLOCKED"]
print("\n[1] Blocked requests by category")
print(blocked.groupby("category").agg(requests=("url", "size"), users=("user", "nunique"))
      .sort_values("requests", ascending=False).to_string())

# ---------- 3. Beaconing: very regular timing to the same domain ----------
print("\n[2] Beaconing (regular, machine-like timing)")
beacons = []
for (user, domain), g in df.groupby(["user", "domain"]):
    if len(g) < BEACON_MIN_HITS:
        continue
    gaps = g["time"].sort_values().diff().dt.total_seconds().dropna()
    cv = gaps.std() / gaps.mean()
    if cv <= BEACON_MAX_CV:
        beacons.append({"user": user, "domain": domain, "hits": len(g),
                        "avg_gap_s": round(gaps.mean(), 1), "gap_std_s": round(gaps.std(), 1),
                        "first_seen": g["time"].min()})
beacons = pd.DataFrame(beacons)
print(beacons.to_string(index=False) if len(beacons) else "  none")

# ---------- 4. Patient zero: what came in right before the first beacon? ----------
print("\n[3] Patient zero (big downloads in the 60 min before beaconing started)")
for b in beacons.itertuples():
    window = df[(df.user == b.user) & (df.time < b.first_seen)
                & (df.time >= b.first_seen - PATIENT_ZERO_WINDOW)
                & (df.action == "ALLOWED") & (df.bytes_down > 1_000_000)]
    for r in window.itertuples():
        mins = (b.first_seen - r.time).total_seconds() / 60
        print(f"  {b.user}: {r.time:%H:%M:%S} downloaded {r.url} "
              f"({r.bytes_down / 1e6:.1f} MB, {r.mime}) → beaconing {mins:.0f} min later")

# ---------- 5. Phishing waves ----------
print("\n[4] Phishing waves (same phishing domain, many users)")
ph = df[df.category == "phishing"]
wave = ph.groupby("domain").agg(users=("user", "nunique"), clicks=("url", "size"),
                                first=("time", "min"), last=("time", "max"))
wave["minutes"] = (wave["last"] - wave["first"]).dt.total_seconds() / 60
print(wave.to_string())
repeat = ph.groupby("user").size()
print("  Users who clicked more than once:", {u: int(n) for u, n in repeat[repeat > 1].items()})

# ---------- 6. Upload spikes after hours ----------
print("\n[5] Uploads (POST/PUT) per user — business hours vs after hours")
up = df[df.method.isin(["POST", "PUT"])].copy()
up["after_hours"] = ~up.time.dt.hour.between(WORK_START, WORK_END - 1)
upload = (up.groupby(["user", "after_hours"])["bytes_up"].sum().div(1e6).round(1)
          .unstack(fill_value=0).rename(columns={False: "day_MB", True: "after_hours_MB"}))
print(upload.to_string())
upload_alerts = upload[upload.get("after_hours_MB", 0) >= UPLOAD_ALERT_MB]

# ---------- 7. Policy violations ----------
print("\n[6] Acceptable-use violations (blocked attempts)")
aup = blocked[blocked.category.isin(["gambling", "social", "risky-file"])]
print(aup.groupby(["user", "category"]).size().unstack(fill_value=0).to_string())

# ---------- 8. Risk summary ----------
print("\n" + "=" * 70 + "\nRISK SUMMARY\n" + "=" * 70)
for b in beacons.itertuples():
    print(f"🔴 HIGH   {b.user}: likely infected — beacon to {b.domain} every ~{b.avg_gap_s:.0f}s")
for d, w in wave.iterrows():
    print(f"🟠 MEDIUM phishing wave: {w.users} users clicked {d} in {w.minutes:.0f} min (blocked)")
for user, r in upload_alerts.iterrows():
    print(f"🟠 MEDIUM {user}: {r.after_hours_MB / 1000:.1f} GB uploaded after hours "
          f"(vs {r.day_MB:.0f} MB in the day)")
gamb = aup[aup.category == "gambling"].groupby("user").size()
for user, n in gamb.items():
    print(f"⚪ LOW    {user}: {n} gambling attempts (policy / HR)")

# ---------- 9. Charts ----------
(HERE / "img").mkdir(exist_ok=True)
plt.rcParams.update({"axes.spines.top": False, "axes.spines.right": False})

normal_user = "kumar"
# 9a. Beacon chart: one dot per request — a normal user vs the infected PC
b0 = beacons.iloc[0]
rows = [(f"{normal_user} — normal browsing", df[df.user == normal_user].time, "#8a8f98"),
        (f"{b0.user} — normal browsing", df[(df.user == b0.user) & (df.domain != b0.domain)].time, "#8a8f98"),
        (f"{b0.user} → {b0.domain}", df[(df.user == b0.user) & (df.domain == b0.domain)].time, "#d1453b")]
fig, ax = plt.subplots(figsize=(10, 3.4))
for i, (_, t, colour) in enumerate(rows):
    ax.scatter(t, [i] * len(t), s=10, color=colour, alpha=0.6)
ax.set_yticks(range(len(rows)), [r[0] for r in rows])
ax.set_ylim(-0.6, len(rows) - 0.4)
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M", tz=df.time.dt.tz))
ax.set_title("Every web request in one day — people browse in bursts, malware ticks like a clock")
fig.tight_layout()
fig.savefig(HERE / "img" / "beaconing.png", dpi=150)

# 9b. Blocked by category
fig, ax = plt.subplots(figsize=(7, 3.5))
counts = blocked.category.value_counts().sort_values()
colours = ["#d1453b" if c in ("malware", "phishing") else "#8a8f98" for c in counts.index]
ax.barh(counts.index, counts.values, color=colours)
for y, v in enumerate(counts.values):
    ax.text(v + 3, y, str(v), va="center")
ax.set_title("Blocked requests by category (red = security threat)")
fig.tight_layout()
fig.savefig(HERE / "img" / "blocked_by_category.png", dpi=150)

# 9c. Uploads by hour for the user with the after-hours spike
if len(upload_alerts):
    who = upload_alerts.index[0]
    u = up[up.user == who]
    by_hour = u.groupby(u.time.dt.hour)["bytes_up"].sum().div(1e6).reindex(range(24), fill_value=0)
    fig, ax = plt.subplots(figsize=(10, 3.2))
    ax.axvspan(WORK_START - 0.5, WORK_END - 0.5, color="#e8f0e8", label="business hours")
    ax.bar(by_hour.index, by_hour.values,
           color=["#d1453b" if not WORK_START <= h < WORK_END else "#4a7bb7" for h in by_hour.index])
    ax.set_xticks(range(0, 24, 2))
    ax.set_xlabel("Hour of day (MYT)")
    ax.set_ylabel("MB uploaded")
    ax.set_title(f"{who}: upload volume to file-sharing by hour")
    day_mb = upload.loc[who, "day_MB"]
    ax.annotate(f"business hours total: {day_mb:.0f} MB", xy=(13.5, by_hour.max() * 0.08),
                ha="center", color="#4a7bb7")
    ax.legend(loc="upper left", frameon=False)
    fig.tight_layout()
    fig.savefig(HERE / "img" / "upload_spike.png", dpi=150)

print("\nCharts saved to img/")
