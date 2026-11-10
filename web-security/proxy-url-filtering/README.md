# Web Proxy – URL Filtering & Proxy Log Threat Hunting (SWSA)

**Objective.** Build a web proxy that enforces a company's internet policy (the open-source version of a Cisco Secure Web Appliance), then hunt through one day of its logs to find threats the blocklist alone doesn't explain.

**Certification link:** Cisco Certified Specialist – Web Content Security (SWSA) — Proxy Services, Identification, URL Categories, Access Policies, Decryption Policies, Malware Defense, Reporting & Tracking

## TL;DR
| Risk | User | What the logs showed | Action |
| --- | --- | --- | --- |
| 🔴 **HIGH** | dzul | Downloaded `PDFConverter_setup.zip` at 10:12 → **3 min later** his PC started contacting a malware domain **every 300 s (±2 s)**, 165 times, until midnight | Isolate PC, reimage, block the download site, scan other PCs for the same file |
| 🟠 **MEDIUM** | 6 users | Phishing wave: **6 people clicked the same fake Office 365 link in 15 min** (all blocked). aina tried **4 times** | Find + delete the email, warn staff, targeted training for aina |
| 🟠 **MEDIUM** | farah | **3.4 GB uploaded** to a file-sharing site between 23:08–23:52 vs **10 MB** during the day | Confirm with farah + manager. Possible data leak or stolen account |
| ⚪ **LOW** | hafiz | 6 attempts to an online gambling site | HR / acceptable-use reminder |

> 💡 **Key lesson:** the proxy **blocked** the malware's traffic 165 times — but blocking isn't the end. The blocks *are the alarm*. The PC is still infected. And the biggest data movement of the day (farah) was **allowed** by the policy. Allowed ≠ safe.

## How a Cisco WSA maps to this lab
| WSA feature | What I used | Where |
| --- | --- | --- |
| Proxy Services | Squid explicit proxy on port 3128 | `squid/squid.conf` |
| Identification Profiles | Proxy login (basic auth) → every log line has a **username** | section 1 |
| URL Categories | Domain blocklists (malware, phishing, gambling, social, file-sharing) | `squid/blocklists/` |
| Access Policies | Ordered rules: security blocks first → acceptable use → allow | section 4 |
| Time-based policy | Social media allowed only 12:00–14:00 | `lunch_time` |
| File-type blocking | Block `.exe .msi .scr .bat .ps1 .vbs` downloads | `risky_files` |
| Decryption Policies | SSL-bump example: decrypt most HTTPS, **never** banking/health | section 5 |
| Reporting & Tracking | Custom log format incl. **upload bytes** + Python analysis | section 6, `analyze.py` |

## Policy (rules run top to bottom, first match wins)
| # | Rule | Result |
| --- | --- | --- |
| 1 | Not logged in | ❌ 407 — login required |
| 2 | Malware / phishing domain | ❌ Block (everyone, always) |
| 3 | Executable file download | ❌ Block |
| 4 | Gambling | ❌ Block |
| 5 | Social media at lunch (12–2 pm, weekdays) | ✅ Allow |
| 6 | Social media other times | ❌ Block |
| 7 | File sharing — Finance team | ✅ Allow (logged) |
| 8 | File sharing — everyone else | ❌ Block |
| 9 | Office network, logged in | ✅ Allow |
| 10 | Anything else | ❌ Block |

✅ **Tested:** I ran this exact `squid.conf` on Squid 6 and checked each rule with `curl` — malware, gambling, social (outside lunch), and `.exe` returned **403**, no login returned **407**, and file sharing was allowed for farah but blocked for dzul.

## Dataset
[`data/access.log`](./data/access.log) — **synthetic** Squid log, 1,521 requests, 10 users, Tue 3 Nov 2026 (MYT).  
Made with [`generate_logs.py`](./generate_logs.py). Bad domains use the reserved `.test` top-level domain, so they aren't real sites.

## Method — 5 checks
| # | Check | Catches | Rule |
| --- | --- | --- | --- |
| 1 | Blocked requests by category | What the policy stopped | — |
| 2 | **Beaconing:** how regular are the gaps between requests? | Malware calling home | ≥ 20 hits and gaps vary < 10% |
| 3 | **Patient zero:** big download < 60 min before beaconing | How the PC got infected | > 1 MB, allowed |
| 4 | **Phishing wave:** many users → same phishing domain | Email campaign | users per domain |
| 5 | **Upload spike:** POST/PUT bytes after hours vs daytime | Data leaving the company | ≥ 500 MB after 8 pm |

Run it yourself:
```bash
pip install pandas matplotlib
python analyze.py
```

## Findings

### 1. 🔴 dzul — infected PC beaconing to a malware server
![Beaconing](./img/beaconing.png)
- Normal browsing (grey) comes in **bursts** and stops when people go home.
- The red line is perfectly even: **one request every 300 seconds, gap std dev 1.9 s**, still going at midnight with nobody at the desk. That's a program on a timer, not a person.
- **Patient zero:** at **10:12:07** dzul downloaded `PDFConverter_setup.zip` (2.4 MB) from a free-tools site. Beaconing began at **10:15:31**.
- ⚠️ **Gap found in the policy:** `.exe` is blocked, but a **`.zip` with an .exe inside** isn't. Fix: block or scan archives from uncategorised sites.

### 2. 🟠 Phishing wave — 6 users in 15 minutes
- The same fake Office 365 login link was clicked by **6 users between 11:41 and 11:56**. This timing = one email sent to many people.
- All 9 clicks were **blocked**, but it shows the email reached inboxes and people trusted it.
- **aina clicked 4 times** — when a page doesn't load, people retry. She needs a quick follow-up, not blame.

### 3. 🟠 farah — 3.4 GB uploaded late at night
![Upload spike](./img/upload_spike.png)
- File sharing is **allowed** for Finance, so nothing was blocked.
- Her normal pattern: 2 small uploads in the day (10 MB). Then **14 uploads totalling 3.4 GB between 23:08 and 23:52**.
- Could be innocent (deadline, audit files) or data theft / a stolen account. **Ask before assuming** — same as a fraud case.

### 4. ⚪ hafiz — gambling attempts
- 6 blocked attempts (lunch + end of day). Online gambling is illegal in Malaysia, so it's a policy and HR matter, not a technical threat.

![Blocked by category](./img/blocked_by_category.png)

## Recommended Response
1. **dzul:** isolate the PC from the network, collect evidence, reimage. Search all proxy logs for the same `.zip` URL and the beacon domain.
2. **Policy fix:** block or sandbox-scan archives (`.zip .rar .7z`) from uncategorised or newly seen domains.
3. **Phishing:** remove the email from all inboxes, block the sender, short awareness message to staff.
4. **farah:** verify with her and her manager. If unexplained, reset password, check login locations, review what was uploaded.
5. **Alerting:** turn checks 2 and 5 into SIEM alerts so they fire in real time, not after a manual review.

## Detection ideas (SOC-style, Splunk conceptual)
**Beaconing:**
```splunk
index=proxy
| sort 0 _time
| streamstats current=f last(_time) as prev by user, domain
| eval gap=_time-prev
| stats count, avg(gap) as avg_gap, stdev(gap) as sd by user, domain
| where count>=20 AND sd/avg_gap<0.1
```

**After-hours upload spike:**
```splunk
index=proxy (method=POST OR method=PUT) (date_hour>=20 OR date_hour<8)
| stats sum(bytes_up) as up by user, domain
| eval up_MB=round(up/1024/1024)
| where up_MB>=500
```

---

# 🔁 Redo it yourself (step by step)

**You need:** Python 3, and **Docker Desktop** for Part A (free). **Time:** Part A ~1 h, Part B ~1.5 h. Part B works without Docker.

### Part A — Run the proxy (1 h)
- [ ] **Read** `squid/squid.conf` top to bottom. For each `http_access` line, say out loud what it does
- [ ] Create the login file: `./squid/make_passwords.sh` (needs `htpasswd`)
- [ ] Start it: `cd squid && docker compose up -d`
- [ ] Test each rule with `curl` (replace the URL each time):
  ```bash
  curl -I -x http://dzul:Lab-Proxy-2026@localhost:3128 http://www.facebook.com/
  ```
  - `http://example.com` → 200 ✅ · `http://www.facebook.com` → 403 (unless it's lunchtime!) · `http://lucky-casino88.test` → 403 · `http://example.com/a.exe` → 403 · no username → 407
  - `http://wetransfer.com` as `farah` → allowed · as `dzul` → 403
- [ ] Watch the log while testing: `docker compose exec squid tail -f /var/log/squid/access.log`
- ✅ **Check:** every 403 shows `TCP_DENIED/403` **with a username**
- 🧠 **Understand:** move `deny cat_social` *above* `allow cat_social lunch_time`. Now social is blocked even at lunch. **Order matters** — same as ACLs in your network labs
- 🧠 **Bonus (Decryption):** read section 5. Why would a bank or hospital site **not** be decrypted? (Privacy law, and the user's trust)

### Part B — Hunt in the logs (1.5 h)
- [ ] Open `data/access.log` in a text editor. Find one line of each: an allowed page, a 403, a POST
- [ ] Label each field using the `logformat` line in `squid.conf`
- [ ] Run `python analyze.py` and read the output **one section at a time**
- [ ] Open the 3 charts in `img/`
- [ ] For each check, find the matching code block in `analyze.py` and explain it in one sentence:
  - **Beaconing** → *"gaps between requests that barely change = a timer"*
  - **Patient zero** → *"look back 60 min before the first beacon for a download"*
  - **Upload spike** → *"compare night uploads to the same person's daytime normal"*
- [ ] **Change one threshold** (e.g. `BEACON_MAX_CV = 0.5`) and run again. What changes? Why?
- 🧠 **Fraud link:** check 5 is the same idea as spotting a customer whose spending suddenly jumps at 2 am — compare to **their own** normal, not everyone's

### Part C — Make it yours (optional)
- [ ] Edit `generate_logs.py` to hide a 5th incident (e.g. someone visiting a new malware domain once). Can your checks catch it? If not, write a new check
- [ ] Rebuild the charts in Power BI or Tableau from `access.log`

### Finish
- [ ] Screenshot your `curl` tests + log output and add them here
- [ ] Write "What I learned" in your own words

## What I learned
- *(write yours here)*

## Files
| File | What it is |
| --- | --- |
| [`squid/squid.conf`](./squid/squid.conf) | Proxy policy (tested on Squid 6) |
| [`squid/blocklists/`](./squid/blocklists) | URL category lists |
| [`squid/docker-compose.yml`](./squid/docker-compose.yml) | Run the proxy in Docker |
| [`squid/make_passwords.sh`](./squid/make_passwords.sh) | Creates lab proxy logins |
| [`generate_logs.py`](./generate_logs.py) | Builds the synthetic log |
| [`data/access.log`](./data/access.log) | Synthetic proxy log |
| [`analyze.py`](./analyze.py) | 5 detection checks + charts |
| [`img/`](./img) | Output charts |
