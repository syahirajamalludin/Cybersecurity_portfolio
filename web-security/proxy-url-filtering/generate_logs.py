"""
Creates a SYNTHETIC Squid access log for one office day (24 h) with 4 hidden incidents.
You don't need to run this — data/access.log is already included.
Run it only if you want to change the story or make a new dataset.

Log format (same as `logformat portfolio` in squid/squid.conf):
  epoch.ms  elapsed_ms  client_ip  user  RESULT/code  bytes_up  bytes_down  method  url  mime
"""
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)
MYT = timezone(timedelta(hours=8))
DAY = datetime(2026, 11, 3, 0, 0, tzinfo=MYT)          # a Tuesday
OUT = Path(__file__).parent / "data" / "access.log"

USERS = {   # user: client IP
    "aina": "10.10.10.11", "amir": "10.10.10.12", "daniel": "10.10.10.13",
    "mei": "10.10.10.14", "ravi": "10.10.10.15", "siti": "10.10.10.16",
    "hafiz": "10.10.20.11", "farah": "10.10.20.12", "dzul": "10.10.20.15",
    "kumar": "10.10.20.16",
}
WORK_SITES = [
    ("outlook.office.com", "/mail/inbox", "text/html"),
    ("teams.microsoft.com", "/api/chat", "application/json"),
    ("www.google.com", "/search?q=report", "text/html"),
    ("github.com", "/org/repo", "text/html"),
    ("stackoverflow.com", "/questions/123", "text/html"),
    ("www.linkedin.com", "/feed", "text/html"),
    ("www.thestar.com.my", "/business", "text/html"),
    ("www.bnm.gov.my", "/publications", "text/html"),
    ("docs.python.org", "/3/library/", "text/html"),
    ("cdn.jsdelivr.net", "/npm/lib.js", "application/javascript"),
]
SOCIAL = ["www.facebook.com", "www.instagram.com", "www.tiktok.com", "x.com"]
lines = []


def log(t, user, result, up, down, method, url, mime, elapsed=None):
    elapsed = elapsed if elapsed is not None else random.randint(20, 900)
    lines.append((t.timestamp(), f"{t.timestamp():.3f} {elapsed:6d} {USERS[user]} {user} "
                  f"{result} {up} {down} {method} {url} {mime}"))


def at(h, m=0, s=0):
    return DAY + timedelta(hours=h, minutes=m, seconds=s)


# ---------- Normal work browsing (09:00-18:00) ----------
for user in USERS:
    for _ in range(random.randint(90, 160)):
        t = at(9) + timedelta(seconds=random.randint(0, 9 * 3600))
        host, path, mime = random.choice(WORK_SITES)
        log(t, user, "TCP_MISS/200", random.randint(300, 2500),
            random.randint(2_000, 400_000), "GET", f"https://{host}{path}", mime)
    # Social media: allowed at lunch, blocked otherwise
    for _ in range(random.randint(0, 6)):
        t = at(12) + timedelta(seconds=random.randint(0, 2 * 3600 - 1))
        log(t, user, "TCP_MISS/200", 900, random.randint(50_000, 900_000), "GET",
            f"https://{random.choice(SOCIAL)}/", "text/html")
    for _ in range(random.randint(0, 3)):
        t = at(random.choice([10, 15, 16]), random.randint(0, 59))
        log(t, user, "TCP_DENIED/403", 700, 3_380, "GET",
            f"https://{random.choice(SOCIAL)}/", "text/html", elapsed=0)

# ---------- Incident 1: dzul downloads fake tool -> malware beacons every ~5 min ----------
log(at(10, 12, 7), "dzul", "TCP_MISS/200", 650, 2_384_112, "GET",
    "http://free-pdf-tools.test/PDFConverter_setup.zip", "application/zip", elapsed=4100)
t = at(10, 15, 31)
while t < at(23, 59, 59):
    log(t, "dzul", "TCP_DENIED/403", random.randint(410, 430), 3_394, "GET",
        "http://update-check.badcdn.test/ping?id=7f3a", "text/html", elapsed=0)
    t += timedelta(seconds=300 + random.uniform(-3, 3))

# ---------- Incident 2: phishing email wave, 11:41-11:58 ----------
clickers = ["aina", "mei", "ravi", "kumar", "siti", "amir"]
for i, user in enumerate(clickers):
    t = at(11, 41 + i * 3, random.randint(0, 50))
    tries = 4 if user == "aina" else 1
    for k in range(tries):
        log(t + timedelta(seconds=k * 25), user, "TCP_DENIED/403", 980, 3_402, "GET",
            "http://office365-verify.test/login?user=" + user, "text/html", elapsed=0)

# ---------- Incident 3: farah - large uploads to file-sharing late at night ----------
for h, m in [(10, 30), (15, 5)]:            # normal daytime: 2 small uploads
    log(at(h, m), "farah", "TCP_MISS/200", random.randint(3_000_000, 6_000_000), 4_200,
        "POST", "https://wetransfer.com/api/upload", "application/json", elapsed=8000)
t = at(23, 8, 40)
for _ in range(14):                           # late night: 14 big uploads
    log(t, "farah", "TCP_MISS/200", random.randint(180_000_000, 300_000_000), 4_200,
        "POST", "https://wetransfer.com/api/upload", "application/json", elapsed=95_000)
    t += timedelta(minutes=random.randint(2, 4))

# ---------- Incident 4: hafiz - repeated gambling attempts ----------
for h, m in [(13, 5), (13, 6), (13, 6), (13, 9), (17, 40), (17, 41)]:
    log(at(h, m, random.randint(0, 59)), "hafiz", "TCP_DENIED/403", 720, 3_376, "GET",
        "http://lucky-casino88.test/", "text/html", elapsed=0)

# ---------- Someone else tries to download an .exe (blocked by file-type rule) ----------
log(at(14, 22, 10), "daniel", "TCP_DENIED/403", 700, 3_378, "GET",
    "http://downloads.example.com/tools/setup.exe", "text/html", elapsed=0)

OUT.parent.mkdir(exist_ok=True)
OUT.write_text("\n".join(l for _, l in sorted(lines)) + "\n")
print(f"Wrote {len(lines)} log lines to {OUT}")
