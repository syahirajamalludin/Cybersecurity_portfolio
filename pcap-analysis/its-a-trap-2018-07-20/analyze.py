"""
PCAP triage in Python — the same steps you'd do in Wireshark, written as code.

Usage:  python analyze.py                      (uses data/trap-lab.pcap)
        python analyze.py path/to/other.pcap   (works on other captures too)
Output: printed report + charts in img/

The 6 steps:
  1. Who is the host?        DHCP hostname, MAC, IP
  2. What's in the capture?  protocol breakdown (Wireshark: Protocol Hierarchy)
  3. Who talks the most?     top conversations by bytes (Wireshark: Conversations)
  4. Any programs downloaded? HTTP bodies starting with "MZ" (= Windows .exe),
                              and files whose name/type LIE about being an .exe
  5. Any beaconing?          repeated connections to one server at a steady interval
  6. Timeline + IOCs         DNS name -> IP, first/last seen, role
"""
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import pandas as pd
from scapy.all import DHCP, DNS, DNSRR, IP, TCP, UDP, Raw, rdpcap

HERE = Path(__file__).parent
PCAP = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "data" / "trap-lab.pcap"
BEACON_MIN_CONNS = 6          # at least this many connections to one server...
BEACON_MAX_CV = 0.10          # ...with gaps this regular (std / mean) = beaconing
EXE_EXT = (".exe", ".dll", ".scr", ".msi", ".bat", ".ps1")

pkts = rdpcap(str(PCAP))
print(f"Loaded {len(pkts)} packets from {PCAP.name}\n")


def ts(x):
    return pd.to_datetime(float(x), unit="s", utc=True)


# ---------- Step 1: who is the host? ----------
hosts = {}
for p in pkts:
    if p.haslayer(DHCP):
        opts = dict(o for o in p[DHCP].options if isinstance(o, tuple) and len(o) == 2)
        if "hostname" in opts:
            mac = p.src
            ip = opts.get("requested_addr", p[IP].src)
            hosts[mac] = (opts["hostname"].decode(errors="ignore"), ip)
print("STEP 1 - Host(s) seen in DHCP")
for mac, (name, ip) in hosts.items():
    print(f"  {name:<18} IP {ip:<15} MAC {mac}")

# ---------- Step 2: protocol breakdown ----------
def proto(p):
    if p.haslayer(DHCP):
        return "DHCP"
    if p.haslayer(DNS):
        return "DNS"
    if p.haslayer(TCP):
        port = {p[TCP].sport, p[TCP].dport}
        if 80 in port:
            return "HTTP (plain text)"
        if 443 in port:
            return "HTTPS (encrypted)"
        return "Other TCP"
    if p.haslayer(UDP):
        return "Other UDP"
    return "Other"


proto_df = pd.DataFrame([(proto(p), len(p)) for p in pkts], columns=["protocol", "bytes"])
proto_sum = proto_df.groupby("protocol").agg(packets=("bytes", "size"), bytes=("bytes", "sum"))
proto_sum = proto_sum.sort_values("bytes", ascending=False)
print("\nSTEP 2 - Protocol breakdown")
print(proto_sum.to_string())

# ---------- DNS map (needed by steps 3-6) ----------
ip_to_name, dns_rows = {}, []
for p in pkts:
    if p.haslayer(DNS) and p[DNS].qr == 1 and p[DNS].ancount:
        for i in range(p[DNS].ancount):
            rr = p[DNS].an[i] if hasattr(p[DNS].an, "__getitem__") else p[DNS].an
            if isinstance(rr, DNSRR) and rr.type == 1:
                name = rr.rrname.decode().rstrip(".")
                ip_to_name[rr.rdata] = name
                dns_rows.append((ts(p.time), name, rr.rdata))
dns = pd.DataFrame(dns_rows, columns=["time", "domain", "ip"])

# ---------- Step 3: conversations ----------
conv = defaultdict(lambda: [0, 0])
for p in pkts:
    if p.haslayer(IP) and p.haslayer(TCP):
        a, b = sorted([p[IP].src, p[IP].dst])
        conv[(a, b)][0] += 1
        conv[(a, b)][1] += len(p)
conv_df = pd.DataFrame([(a, b, n, by) for (a, b), (n, by) in conv.items()],
                       columns=["host_a", "host_b", "packets", "bytes"])
conv_df["remote"] = conv_df.apply(lambda r: r.host_b if r.host_a.startswith("10.") else r.host_a, axis=1)
conv_df["domain"] = conv_df.remote.map(ip_to_name).fillna("?")
conv_df = conv_df.sort_values("bytes", ascending=False)
print("\nSTEP 3 - Top TCP conversations")
print(conv_df[["remote", "domain", "packets", "bytes"]].head(8).to_string(index=False))

# ---------- Rebuild TCP streams -> HTTP requests & responses ----------
streams = defaultdict(lambda: {"c": {}, "s": {}, "start": None, "client": None})
for p in pkts:
    if not (p.haslayer(TCP) and p.haslayer(IP)):
        continue
    t = p[TCP]
    if 80 not in (t.sport, t.dport):
        continue
    client_side = t.dport == 80
    key = (p[IP].src, t.sport, p[IP].dst, t.dport) if client_side else (p[IP].dst, t.dport, p[IP].src, t.sport)
    s = streams[key]
    s["start"] = s["start"] or p.time
    if p.haslayer(Raw):
        s["c" if client_side else "s"][t.seq] = bytes(p[Raw].load)


def joined(d):
    return b"".join(d[k] for k in sorted(d))


http = []
for (cip, cport, sip, sport), s in streams.items():
    req, resp = joined(s["c"]), joined(s["s"])
    if not req:
        continue
    head = req.split(b"\r\n\r\n")[0].decode(errors="ignore").split("\r\n")
    method, path = (head[0].split(" ") + ["", ""])[:2]
    hdr = {h.split(":", 1)[0].lower(): h.split(":", 1)[1].strip() for h in head[1:] if ":" in h}
    r_head, _, body = resp.partition(b"\r\n\r\n")
    r_lines = r_head.decode(errors="ignore").split("\r\n")
    r_hdr = {h.split(":", 1)[0].lower(): h.split(":", 1)[1].strip() for h in r_lines[1:] if ":" in h}
    http.append({
        "time": ts(s["start"]), "client": cip, "server": sip,
        "host": hdr.get("host", ip_to_name.get(sip, sip)), "method": method, "path": path,
        "user_agent": hdr.get("user-agent", ""),
        "status": r_lines[0].split(" ")[1] if len(r_lines[0].split(" ")) > 1 else "",
        "content_type": r_hdr.get("content-type", ""), "size": len(body),
        "is_exe": body[:2] == b"MZ",
    })
http = pd.DataFrame(http).sort_values("time").reset_index(drop=True)

# ---------- Step 4: executable downloads ----------
exe = http[http.is_exe].copy()
exe["disguised"] = ~exe.path.str.lower().str.endswith(EXE_EXT)
print("\nSTEP 4 - Windows programs (body starts with 'MZ') downloaded over HTTP")
for r in exe.itertuples():
    flag = "  <-- DISGUISED: name/type says it's not a program!" if r.disguised else ""
    print(f"  {r.time:%H:%M:%S}  http://{r.host}{r.path}  ({r.size:,} bytes, Content-Type: {r.content_type}){flag}")

# ---------- Step 5: beaconing ----------
beacons = []
for (host, method, path), g in http.groupby(["host", "method", "path"]):
    if len(g) < BEACON_MIN_CONNS:
        continue
    gaps = g.time.diff().dt.total_seconds().dropna()
    cv = gaps.std() / gaps.mean()
    if cv <= BEACON_MAX_CV:
        beacons.append({"host": host, "request": f"{method} {path}", "count": len(g),
                        "avg_gap_sec": round(gaps.mean(), 1), "gap_std_sec": round(gaps.std(), 1),
                        "cv": round(cv, 3), "user_agent": g.user_agent.iloc[0],
                        "first": g.time.min(), "last": g.time.max()})
beacons = pd.DataFrame(beacons)
print("\nSTEP 5 - Beaconing (steady repeated check-ins)")
print(beacons.drop(columns=["first", "last"]).to_string(index=False) if len(beacons) else "  none found")

# ---------- Step 6: timeline + IOCs ----------
bad_hosts = set(exe.host) | set(beacons.host if len(beacons) else [])
first_exe = exe.time.min() if len(exe) else None
iocs = []
for host in sorted(bad_hosts, key=lambda h: http[http.host == h].time.min()):
    g = http[http.host == host]
    if len(beacons) and host in set(beacons.host):
        role = "C2 server (beaconing)"
    elif first_exe is not None and g.time.min() <= first_exe:
        role = "Initial download (fake site)"
    else:
        role = "Second-stage download"
    ip = g.server.iloc[0]
    iocs.append({"domain": host, "ip": ip, "role": role, "requests": len(g),
                 "first_seen": f"{g.time.min():%H:%M:%S}", "last_seen": f"{g.time.max():%H:%M:%S}"})
iocs = pd.DataFrame(iocs)
print("\nSTEP 6 - Indicators of compromise (IOCs)")
print(iocs.to_string(index=False))

# ---------- Charts ----------
img = HERE / "img"
img.mkdir(exist_ok=True)
RED, ORANGE, GREY, BLUE = "#d62728", "#ff7f0e", "#9e9e9e", "#1f77b4"
role_color = {"Initial download (fake site)": ORANGE, "Second-stage download": ORANGE,
              "C2 server (beaconing)": RED}


def style(ax):
    ax.spines[["top", "right"]].set_visible(False)


# Chart 1: top conversations
top = conv_df.head(8).iloc[::-1]
host_role = dict(zip(iocs.ip, iocs.role)) if len(iocs) else {}
fig, ax = plt.subplots(figsize=(9, 4.2))
ax.barh([f"{d}\n{ip}" for d, ip in zip(top.domain, top.remote)], top.bytes / 1024,
        color=[role_color.get(host_role.get(ip), GREY) for ip in top.remote])
for y, (by, ip) in enumerate(zip(top.bytes, top.remote)):
    role = host_role.get(ip, "")
    ax.text(by / 1024 + 5, y, f"{by / 1024:,.0f} KB" + (f"  ← {role}" if role else ""), va="center", fontsize=8.5)
ax.set_xlim(0, top.bytes.max() / 1024 * 1.6)
ax.set_xlabel("Data exchanged (KB)")
ax.set_title("Top conversations (orange = malware download, red = attacker's server)")
ax.tick_params(axis="y", labelsize=8)
style(ax)
fig.tight_layout()
fig.savefig(img / "top_conversations.png", dpi=150)

# Chart 2: infection timeline
fig, ax = plt.subplots(figsize=(10, 4))
rows = ["normal browsing (HTTPS)"] + list(iocs.domain)
https_times = [ts(p.time) for p in pkts if p.haslayer(TCP) and p[TCP].dport == 443 and p[TCP].flags == "S"]
ax.scatter(https_times, [0] * len(https_times), color=GREY, s=40, label="normal HTTPS visit")
for i, r in enumerate(iocs.itertuples(), start=1):
    g = http[http.host == r.domain]
    exe_g = g[g.is_exe]
    other = g[~g.is_exe]
    ax.scatter(other.time, [i] * len(other), color=role_color[r.role], s=30, marker="|" if "C2" in r.role else "o",
               linewidths=2)
    ax.scatter(exe_g.time, [i] * len(exe_g), color=ORANGE, s=160, marker="*", edgecolor="black", zorder=3)
    for e in exe_g.itertuples():
        name = e.path.rsplit("/", 1)[-1]
        ax.annotate(f"{name}" + ("  (really an .exe!)" if not name.endswith(EXE_EXT) else ""),
                    (e.time, i), xytext=(8, 8), textcoords="offset points", fontsize=8.5)
if len(beacons):
    b = beacons.iloc[0]
    ax.annotate(f"{b['count']} check-ins, every ~{b['avg_gap_sec']:.0f} s",
                (b["last"], rows.index(b["host"])), xytext=(-140, 10), textcoords="offset points", fontsize=8.5)
ax.set_yticks(range(len(rows)), rows, fontsize=8.5)
ax.set_ylim(len(rows) - 0.5, -0.5)
ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M"))
ax.set_xlabel("Time (UTC)")
ax.set_title("Infection timeline: fake download → disguised 2nd stage → C2 check-ins")
ax.grid(axis="x", alpha=0.3)
style(ax)
fig.tight_layout()
fig.savefig(img / "infection_timeline.png", dpi=150)

# Chart 3: beacon regularity vs normal browsing
if len(beacons):
    b = beacons.iloc[0]
    g = http[(http.host == b["host"])]
    gaps = g.time.diff().dt.total_seconds().dropna().values
    normal_starts = sorted(https_times)
    normal_gaps = pd.Series(normal_starts).diff().dt.total_seconds().dropna().values
    fig, ax = plt.subplots(figsize=(9, 3.8))
    ax.plot(range(1, len(gaps) + 1), gaps, "o-", color=RED, label=f"{b['host']} (C2)")
    ax.plot(range(1, len(normal_gaps) + 1), normal_gaps, "s--", color=GREY, alpha=0.8, label="normal browsing")
    ax.set_xlabel("Connection number")
    ax.set_ylabel("Seconds since previous")
    ax.set_title("A machine keeps time, a human doesn't: C2 gaps stay flat at ~60 s")
    ax.legend(fontsize=8)
    ax.grid(alpha=0.3)
    style(ax)
    fig.tight_layout()
    fig.savefig(img / "beacon_intervals.png", dpi=150)

print(f"\nCharts saved to {img}")
