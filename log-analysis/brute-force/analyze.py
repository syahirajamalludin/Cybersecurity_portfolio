"""
Brute-force & credential-stuffing detection on authentication logs (SIEM simulation).

Usage:  python analyze.py
Input:  data/logs.csv  (timestamp, user, src_ip, action, protocol)
Output: printed summary + charts in img/

Two attack patterns:
  - Brute-force:        ONE account, MANY password guesses
  - Credential stuffing: MANY accounts, 1-2 tries each (using leaked passwords)
"""
from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd

HERE = Path(__file__).parent
WINDOW = pd.Timedelta("10min")   # time window for all rules
FAIL_THRESHOLD = 5               # brute-force: fails on ONE account in the window
USER_THRESHOLD = 5               # stuffing: DIFFERENT accounts tried in the window
BOT_STD_SEC = 5                  # timing this regular (std dev of gaps) = scripted

# ---------- 1. Load ----------
df = pd.read_csv(HERE / "data" / "logs.csv", parse_dates=["timestamp"])
df = df.sort_values("timestamp").reset_index(drop=True)


def max_in_window(times, values=None):
    """Max count (or max distinct values) seen inside any WINDOW-long period."""
    best = 0
    for t in times:
        mask = (times >= t) & (times < t + WINDOW)
        best = max(best, values[mask].nunique() if values is not None else mask.sum())
    return best


# ---------- 2. Summarise per source IP ----------
rows = []
for ip, g in df.groupby("src_ip"):
    fails = g[g.action == "FAIL"]
    first_fail = fails.timestamp.min()
    success_after = g[(g.action == "SUCCESS") & (g.timestamp > first_fail)]

    # Check 1: brute-force -> most fails on a single account in 10 min
    max_fails_one_user = max(max_in_window(f.timestamp) for _, f in fails.groupby("user"))
    # Check 2: credential stuffing -> how many different accounts in 10 min
    max_users = max_in_window(g.timestamp, g.user)
    # Check 3: did a login succeed after the failures?
    compromised = ", ".join(success_after.user.unique())
    # Check 4: timing -> perfectly even gaps = a script
    gaps = g.timestamp.diff().dt.total_seconds().dropna()

    rows.append({
        "src_ip": ip,
        "accounts": g.user.nunique(),
        "fails": len(fails),
        "max_fails_1_acct_10min": max_fails_one_user,
        "max_accounts_10min": max_users,
        "avg_gap_sec": round(gaps.mean(), 1),
        "gap_std_sec": round(gaps.std(), 1),
        "success_after_fails": compromised or "-",
    })

summary = pd.DataFrame(rows)


def attack_type(r):
    if r.max_accounts_10min >= USER_THRESHOLD:
        return "Credential stuffing"
    if r.max_fails_1_acct_10min >= FAIL_THRESHOLD:
        return "Brute-force"
    return "Normal"


def behaviour(r):
    return "Bot" if r.gap_std_sec <= BOT_STD_SEC else "Human"


def risk(r):
    attack = r.attack_type != "Normal"
    got_in = r.success_after_fails != "-"
    if attack and got_in:
        return "HIGH"
    if attack:
        return "MEDIUM"
    if got_in:
        return "LOW"
    return "INFO"


summary["attack_type"] = summary.apply(attack_type, axis=1)
summary["behaviour"] = summary.apply(behaviour, axis=1)
summary["risk"] = summary.apply(risk, axis=1)
rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
summary = summary.sort_values(["risk", "fails"], key=lambda s: s.map(rank) if s.name == "risk" else -s)

pd.set_option("display.width", 250)
print(summary.to_string(index=False))

# ---------- 3. Charts ----------
img = HERE / "img"
img.mkdir(exist_ok=True)
COLORS = {"HIGH": "#d62728", "MEDIUM": "#ff7f0e", "LOW": "#7f7f7f", "INFO": "#7f7f7f"}


def label(r):
    who = df[df.src_ip == r.src_ip].user.iloc[0] if r.accounts == 1 else f"{r.accounts} accounts"
    return f"{r.src_ip}\n({who})"


def style(ax):
    ax.spines[["top", "right"]].set_visible(False)


# Chart 1: failed logins by source IP
fig, ax = plt.subplots(figsize=(9, 4.2))
bars = ax.barh([label(r) for r in summary.itertuples()], summary.fails,
               color=[COLORS[r] for r in summary.risk])
for b, r in zip(bars, summary.itertuples()):
    text = f"{r.fails} fails · {r.attack_type} · {r.behaviour}"
    if r.success_after_fails != "-":
        text += f"  → {r.success_after_fails} SUCCESS"
    ax.text(b.get_width() + 0.2, b.get_y() + b.get_height() / 2, text, va="center", fontsize=9)
ax.invert_yaxis()
ax.set_xlim(0, summary.fails.max() * 2.1)
ax.set_xlabel("Failed login attempts")
ax.set_title("Failed SSH logins by source IP  (red = attacker got in)")
style(ax)
fig.tight_layout()
fig.savefig(img / "top_ips.png", dpi=150)

# Chart 2: attack-type map -> brute-force vs credential stuffing
fig, ax = plt.subplots(figsize=(7.5, 5))
ax.axhspan(FAIL_THRESHOLD, 12, xmax=0.35, color="#d62728", alpha=0.06)
ax.axvspan(USER_THRESHOLD, 15, ymax=0.35, color="#1f77b4", alpha=0.06)
ax.text(1.2, 10.8, "BRUTE-FORCE ZONE\none account, many guesses", fontsize=9, color="#d62728")
ax.text(8.2, 3.2, "CREDENTIAL-STUFFING ZONE\nmany accounts, few tries each", fontsize=9, color="#1f77b4")
for r in summary.itertuples():
    ax.scatter(r.max_accounts_10min, r.max_fails_1_acct_10min, s=220,
               color=COLORS[r.risk], edgecolor="black", zorder=3)
    ax.annotate(f"{r.src_ip}\n{r.attack_type}", (r.max_accounts_10min, r.max_fails_1_acct_10min),
                xytext=(10, -4), textcoords="offset points", fontsize=8.5, va="top")
ax.set_xlim(0, 15)
ax.set_ylim(0, 12)
ax.set_xlabel("Different accounts tried (in 10 min)")
ax.set_ylabel("Most fails on one account (in 10 min)")
ax.set_title("Two attacks, two fingerprints")
style(ax)
fig.tight_layout()
fig.savefig(img / "attack_types.png", dpi=150)

# Chart 3: timeline of every login attempt, one row per IP
fig, ax = plt.subplots(figsize=(10, 4.2))
order = list(summary.src_ip)
for i, ip in enumerate(order):
    g = df[df.src_ip == ip]
    f, s = g[g.action == "FAIL"], g[g.action == "SUCCESS"]
    ax.scatter(f.timestamp, [i] * len(f), marker="x", color="#d62728", s=45,
               label="FAIL" if i == 0 else None)
    ax.scatter(s.timestamp, [i] * len(s), marker="o", color="#2ca02c", s=90,
               edgecolor="black", zorder=3, label="SUCCESS" if i == 0 else None)
ax.set_yticks(range(len(order)), [label(r) for r in summary.itertuples()])
ax.set_ylim(len(order) - 0.5, -0.5)
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.set_xlabel("Time (UTC, 13 Jun 2025)")
ax.set_title("Login attempts over time")
ax.legend(loc="lower left", fontsize=8)
ax.grid(axis="x", alpha=0.3)
style(ax)
fig.tight_layout()
fig.savefig(img / "fails_over_time.png", dpi=150)

print(f"\nCharts saved to {img}")
