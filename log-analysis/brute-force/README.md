# Log Analysis – Brute-Force Detection (SIEM Simulation)

**Objective.** Detect brute-force login behavior and potential compromise using simple log analysis (Python/pandas).

## TL;DR
| Risk | Source IP | Account | What happened | Action |
| --- | --- | --- | --- | --- |
| 🔴 **HIGH** | `203.0.113.10` | alice | 6 fails in ~4 min → **SUCCESS** | Treat as compromised: reset password, kill sessions, review activity |
| 🟠 **MEDIUM** | `192.0.2.55` | service | 9 fails, **exactly 27 sec apart** → no success | Automated attack: block IP, harden service account |
| ⚪ **LOW** | `198.51.100.7` | bob | 4 fails, irregular timing → success | Likely a forgotten password: confirm with user |

## Dataset
Synthetic SSH auth logs: [`data/logs.csv`](./data/logs.csv) — 21 events, 3 source IPs, 13 Jun 2025 10:00–10:20 UTC  
Fields: `timestamp, user, src_ip, action, protocol`

## Method
1. Loaded the CSV into Python (pandas) and sorted events by time.
2. Counted failed logins per `src_ip`.
3. Checked the **max fails inside any 10-minute window** against a threshold of **5**.
4. Flagged IPs where **failures are followed by a SUCCESS** (potential account takeover).
5. Measured the **time gap between attempts** — perfectly even gaps point to a script, uneven gaps to a human.

Run it yourself:
```bash
pip install pandas matplotlib
python analyze.py
```

## Findings

### 1. 🔴 203.0.113.10 → alice — possible compromise
- 6 failed SSH logins between 10:00:12 and 10:04:09, then a **successful login at 10:05:55**.
- Crosses the 5-fails threshold **and** ends in success — the classic brute-force / credential-stuffing pattern.
- **Risk:** the attacker likely now has access to alice's account.

### 2. 🟠 192.0.2.55 → service — automated brute-force, not (yet) successful
- 9 failed logins in 3.5 minutes, the highest count of any IP.
- Attempts are **exactly 27 seconds apart** (std dev = 0 sec) → this is a bot, not a person.
- Targets a **service account**, which often has weak or shared passwords and no MFA.
- No success seen, but the attack was still running when the log ended.

### 3. ⚪ 198.51.100.7 → bob — likely benign
- 4 fails then success, **below the threshold**.
- Timing is irregular (3 quick tries, a 3.5-minute pause, then 2 more) — looks like a human remembering their password.
- Worth a quick check with the user, but low priority.

> 💡 **Why the top offender isn't the top risk:** `192.0.2.55` has the most failures, but `203.0.113.10` is more urgent because it actually got in. Ranking alerts only by volume would miss this — the same lesson as in fraud detection, where a successful fraudulent transaction matters more than many declined ones.

## Charts
![Failed logins by source IP](./img/top_ips.png)

![Login attempts over time](./img/fails_over_time.png)

## Recommended Response
1. **alice:** force a password reset, end active sessions, review what was accessed after 10:05:55, enable MFA.
2. **192.0.2.55:** block at the firewall; add fail2ban (or similar) rate-limiting on SSH.
3. **service account:** switch to key-based SSH auth and disable password login.
4. **bob:** confirm with the user that the login was theirs.

## Detection Ideas (SOC-style)
**Splunk (conceptual):**
```splunk
index=auth action=FAIL
| bin _time span=10m
| stats count by src_ip, user, _time
| where count>=5
```

**Brute-force followed by success:**
```splunk
index=auth
| stats count(eval(action="FAIL")) as fails,
        count(eval(action="SUCCESS")) as successes by src_ip, user
| where fails>=5 AND successes>0
```

## Files
| File | What it is |
| --- | --- |
| [`analyze.py`](./analyze.py) | Detection logic + chart generation |
| [`data/logs.csv`](./data/logs.csv) | Sample auth logs |
| [`img/`](./img) | Output charts |
