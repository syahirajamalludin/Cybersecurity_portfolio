"""
Brute-force detection on authentication logs (SIEM simulation).

Usage:  python analyze.py
Input:  data/logs.csv  (timestamp, user, src_ip, action, protocol)
Output: printed summary + charts in img/
"""
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import pandas as pd

HERE = Path(__file__).parent
FAIL_THRESHOLD = 5          # failed attempts that count as brute-force
WINDOW = pd.Timedelta("10min")  # time window for the threshold

# ---------- 1. Load ----------
df = pd.read_csv(HERE / "data" / "logs.csv", parse_dates=["timestamp"])
df = df.sort_values("timestamp")

# ---------- 2. Summarise per source IP ----------
rows = []
for ip, g in df.groupby("src_ip"):
    fails = g[g.action == "FAIL"]
    success = g[g.action == "SUCCESS"]
    first_fail, last_fail = fails.timestamp.min(), fails.timestamp.max()

    # Max fails seen inside any 10-minute window
    max_in_window = max(
        ((fails.timestamp >= t) & (fails.timestamp < t + WINDOW)).sum()
        for t in fails.timestamp
    )
    # Did a SUCCESS come after the failures?
    success_after = success[success.timestamp > first_fail]

    gaps = fails.timestamp.diff().dt.total_seconds().dropna()

    rows.append({
        "src_ip": ip,
        "user": ", ".join(g.user.unique()),
        "fails": len(fails),
        "max_fails_10min": max_in_window,
        "avg_gap_sec": round(gaps.mean(), 1),
        "gap_std_sec": round(gaps.std(), 1),
        "success_after_fails": not success_after.empty,
        "duration": last_fail - first_fail,
    })

summary = pd.DataFrame(rows).sort_values("fails", ascending=False)


def verdict(r):
    brute = r.max_fails_10min >= FAIL_THRESHOLD
    if brute and r.success_after_fails:
        return "HIGH - brute-force then SUCCESS (possible compromise)"
    if brute:
        return "MEDIUM - brute-force, no success (block / monitor)"
    if r.success_after_fails:
        return "LOW - few fails then success (likely forgotten password)"
    return "INFO"


summary["risk"] = summary.apply(verdict, axis=1)

pd.set_option("display.width", 200)
print(summary.to_string(index=False))

# ---------- 3. Charts ----------
img = HERE / "img"
img.mkdir(exist_ok=True)
colors = {"HIGH": "#d62728", "MEDIUM": "#ff7f0e", "LOW": "#7f7f7f", "INFO": "#7f7f7f"}

# Chart 1: failed logins by source IP
fig, ax = plt.subplots(figsize=(8, 4))
bar_colors = [colors[r.split(" ")[0]] for r in summary.risk]
bars = ax.barh(summary.src_ip, summary.fails, color=bar_colors)
ax.axvline(FAIL_THRESHOLD, ls="--", color="black", lw=1)
ax.text(FAIL_THRESHOLD + 0.1, -0.45, f"threshold = {FAIL_THRESHOLD}", fontsize=8)
for b, r in zip(bars, summary.itertuples()):
    label = f"{r.fails} fails ({r.user})" + ("  → SUCCESS" if r.success_after_fails else "")
    ax.text(max(b.get_width(), FAIL_THRESHOLD) + 0.15, b.get_y() + b.get_height() / 2, label, va="center", fontsize=9)
ax.invert_yaxis()
ax.set_xlim(0, summary.fails.max() + 4)
ax.set_xlabel("Failed login attempts")
ax.set_title("Failed SSH logins by source IP")
ax.spines[["top", "right"]].set_visible(False)
fig.tight_layout()
fig.savefig(img / "top_ips.png", dpi=150)

# Chart 2: timeline of every login attempt, one row per IP
fig, ax = plt.subplots(figsize=(9, 3.5))
order = list(summary.src_ip)
for i, ip in enumerate(order):
    g = df[df.src_ip == ip]
    f, s = g[g.action == "FAIL"], g[g.action == "SUCCESS"]
    ax.scatter(f.timestamp, [i] * len(f), marker="x", color="#d62728", s=50,
               label="FAIL" if i == 0 else None)
    ax.scatter(s.timestamp, [i] * len(s), marker="o", color="#2ca02c", s=90,
               edgecolor="black", zorder=3, label="SUCCESS" if i == 0 else None)
ax.set_yticks(range(len(order)), [f"{ip}\n({df[df.src_ip == ip].user.iloc[0]})" for ip in order])
ax.set_ylim(len(order) - 0.5, -0.5)
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.set_xlabel("Time (UTC, 13 Jun 2025)")
ax.set_title("Login attempts over time")
ax.legend(loc="upper left", fontsize=8)
ax.grid(axis="x", alpha=0.3)
ax.spines[["top", "right"]].set_visible(False)
fig.tight_layout()
fig.savefig(img / "fails_over_time.png", dpi=150)

print(f"\nCharts saved to {img}")
