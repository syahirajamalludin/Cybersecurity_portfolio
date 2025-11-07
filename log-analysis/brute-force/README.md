# Log Analysis – Brute-Force Detection (SIEM Simulation)

**Objective.** Detect brute-force login behavior and potential compromise using simple log analysis (Excel/Python).

## Dataset
Synthetic auth logs: `data/logs.csv`  
Fields: `timestamp, user, src_ip, action, protocol`

## Method
1. Ingested the CSV into Excel (or Python/pandas).
2. Counted failed logins by `src_ip` to identify top offenders.
3. Bucketed events into 5-minute windows to reveal spikes.
4. Flagged IPs where **many FAILs are followed by a SUCCESS** (potential account takeover).

## Findings
- **Top offending IP:** (fill from your analysis)
- **Pattern:** ≥5 failed attempts within ~10 minutes, then a **SUCCESS** on a user (possible compromise).
- **Risk:** Likely credential stuffing / brute-force followed by successful auth.

## Artifacts
(Upload charts later to `./img/` and update these links)
- ![Top IPs](./img/top_ips.png)
- ![Fails over time](./img/fails_over_time.png)

## Detection Ideas (SOC-style)
- **Splunk (conceptual):**
  ```splunk
  index=auth action=FAIL | stats count by src_ip | where count>=5
