"""
Builds a SAFE, synthetic PCAP that recreates the "It's a trap!" story:
a user looking for free software lands on a fake download site, runs setup.exe,
and the PC starts talking to an attacker's server.

Usage:  python generate_pcap.py
Output: data/trap-lab.pcap  (open it in Wireshark)

Safety: every "file" in this capture is random bytes. setup.exe only *starts*
with the 2 letters "MZ" (the Windows .exe signature) so detection rules have
something to find. Nothing here can run.
All IPs are documentation ranges (RFC 5737); all domains end in .test (RFC 2606).
"""
import random
from pathlib import Path

from scapy.all import (BOOTP, DHCP, DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw,
                       wrpcap)

random.seed(20180720)
OUT = Path(__file__).parent / "data" / "trap-lab.pcap"
START = 1794474000.0  # 2026-11-12 09:00:00 UTC

# ---------- The cast ----------
VICTIM_IP, VICTIM_MAC, HOSTNAME = "10.7.20.101", "00:1e:4f:7a:20:18", "DESKTOP-TRAP01"
GW_IP, GW_MAC = "10.7.20.1", "00:0c:29:01:01:01"   # router + DNS + DHCP server
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0 Safari/537.36"

SITES = {
    # domain                          : (ip,              role)
    "news.example.test":                ("198.51.100.10", "normal"),
    "mail.example.test":                ("198.51.100.11", "normal"),
    "search.example.test":              ("198.51.100.12", "normal"),
    "cdn.example.test":                 ("198.51.100.13", "normal"),
    "free-pdf-converter-download.test": ("203.0.113.45",  "fake download site"),
    "cdn-update-check.test":            ("203.0.113.46",  "second-stage server"),
    "api-telemetry-sync.test":          ("192.0.2.77",    "C2 server"),
}

packets = []
t = START


def stamp(pkt, at):
    pkt.time = at
    packets.append(pkt)


def eth(src_is_victim=True):
    return Ether(src=VICTIM_MAC, dst=GW_MAC) if src_is_victim else Ether(src=GW_MAC, dst=VICTIM_MAC)


def dhcp_request(at):
    """The PC announces its hostname -> how analysts identify the infected host."""
    p = (Ether(src=VICTIM_MAC, dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
         / UDP(sport=68, dport=67)
         / BOOTP(chaddr=bytes.fromhex(VICTIM_MAC.replace(":", "")), xid=random.getrandbits(32))
         / DHCP(options=[("message-type", "request"), ("requested_addr", VICTIM_IP),
                         ("hostname", HOSTNAME), "end"]))
    stamp(p, at)
    ack = (Ether(src=GW_MAC, dst=VICTIM_MAC) / IP(src=GW_IP, dst=VICTIM_IP) / UDP(sport=67, dport=68)
           / BOOTP(op=2, yiaddr=VICTIM_IP, chaddr=bytes.fromhex(VICTIM_MAC.replace(":", "")))
           / DHCP(options=[("message-type", "ack"), ("server_id", GW_IP), ("router", GW_IP),
                           ("name_server", GW_IP), "end"]))
    stamp(ack, at + 0.003)


def dns_lookup(domain, at):
    qid = random.getrandbits(16)
    sport = random.randint(49152, 65535)
    q = eth() / IP(src=VICTIM_IP, dst=GW_IP) / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=domain))
    r = (eth(False) / IP(src=GW_IP, dst=VICTIM_IP) / UDP(sport=53, dport=sport)
         / DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname=domain),
               an=DNSRR(rrname=domain, ttl=300, rdata=SITES[domain][0])))
    stamp(q, at)
    stamp(r, at + 0.012)
    return at + 0.02


def tcp_session(server_ip, dport, request, response, at, rtt=0.04):
    """A complete TCP conversation: handshake, request, response (split into segments), close."""
    sport = random.randint(49152, 65535)
    c_seq, s_seq = random.getrandbits(31), random.getrandbits(31)
    C = lambda **kw: eth() / IP(src=VICTIM_IP, dst=server_ip) / TCP(sport=sport, dport=dport, **kw)
    S = lambda **kw: eth(False) / IP(src=server_ip, dst=VICTIM_IP) / TCP(sport=dport, dport=sport, **kw)

    stamp(C(flags="S", seq=c_seq), at)
    stamp(S(flags="SA", seq=s_seq, ack=c_seq + 1), at + rtt / 2)
    c_seq, s_seq = c_seq + 1, s_seq + 1
    stamp(C(flags="A", seq=c_seq, ack=s_seq), at + rtt)
    at += rtt + 0.001

    stamp(C(flags="PA", seq=c_seq, ack=s_seq) / Raw(request), at)
    c_seq += len(request)
    at += rtt
    for i in range(0, len(response), 1460):
        chunk = response[i:i + 1460]
        stamp(S(flags="PA" if i + 1460 >= len(response) else "A", seq=s_seq, ack=c_seq) / Raw(chunk), at)
        s_seq += len(chunk)
        at += 0.0004
        if (i // 1460) % 2 == 1:
            stamp(C(flags="A", seq=c_seq, ack=s_seq), at)
    stamp(C(flags="FA", seq=c_seq, ack=s_seq), at + 0.01)
    stamp(S(flags="FA", seq=s_seq, ack=c_seq + 1), at + 0.01 + rtt / 2)
    stamp(C(flags="A", seq=c_seq + 1, ack=s_seq + 1), at + 0.01 + rtt)
    return at + 0.02 + rtt


def http_get(domain, path, body, ctype, at, referer=None):
    req = f"GET {path} HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {UA}\r\nAccept: */*\r\n"
    if referer:
        req += f"Referer: {referer}\r\n"
    req += "Connection: close\r\n\r\n"
    resp = (f"HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: {ctype}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode() + body
    return tcp_session(SITES[domain][0], 80, req.encode(), resp, at)


def http_post(domain, path, body, reply, at, ua):
    req = (f"POST {path} HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {ua}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n"
           "Connection: close\r\n\r\n").encode() + body
    resp = (f"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(reply)}\r\n"
            "Connection: close\r\n\r\n").encode() + reply
    return tcp_session(SITES[domain][0], 80, req, resp, at, rtt=0.18)


def https_visit(domain, size, at):
    """Normal encrypted browsing: we only see sizes, not content (like real TLS)."""
    hello = b"\x16\x03\x01\x02\x00\x01" + random.randbytes(500)
    return tcp_session(SITES[domain][0], 443, hello, b"\x17\x03\x03" + random.randbytes(size), at)


def html(title, extra=""):
    return f"<html><head><title>{title}</title></head><body>{extra}</body></html>".encode()


def fake_exe(size):
    """Harmless random bytes that merely START like a Windows program (MZ header)."""
    return b"MZ\x90\x00" + b"\x00" * 60 + b"This program cannot be run in DOS mode.\r\n" + random.randbytes(size)


# ---------- The story ----------
dhcp_request(t)                                                        # 09:00 PC joins the network
t += 2
for d, size in [("mail.example.test", 42_000), ("news.example.test", 180_000),
                ("cdn.example.test", 260_000), ("news.example.test", 95_000)]:
    t = https_visit(d, size, dns_lookup(d, t)) + random.uniform(20, 70)

# ~09:03 user searches for a free PDF converter
t = https_visit("search.example.test", 38_000, dns_lookup("search.example.test", t)) + 8

# ~09:03 lands on the fake download site (plain HTTP - a red flag in itself)
site = "free-pdf-converter-download.test"
t = dns_lookup(site, t)
t = http_get(site, "/", html("Free PDF Converter 2026 - Download Now",
             '<a href="/download/setup.exe">DOWNLOAD FREE</a>'), "text/html", t) + 14
t = http_get(site, "/download/setup.exe", fake_exe(184_000), "application/octet-stream", t,
             referer=f"http://{site}/")
infection = t + 41                                                     # user runs setup.exe ~40 s later

# ~09:04 malware fetches a 2nd stage disguised as an image
t = dns_lookup("cdn-update-check.test", infection)
t = http_get("cdn-update-check.test", "/img/logo.png", fake_exe(96_000), "image/png", t + 1)

# ~09:04 onwards: C2 check-ins every ~60 s, mixed with normal browsing
c2 = "api-telemetry-sync.test"
t = dns_lookup(c2, t + 3)
beacon_ua = "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)"      # old, odd UA = clue
next_beacon = t
normal = [("news.example.test", 120_000), ("mail.example.test", 30_000), ("cdn.example.test", 210_000)]
for n in range(30):
    body = f"id={HOSTNAME}&os=win10&v=2.1&n={n}".encode()
    http_post(c2, "/gate.php", body, b"OK" if n % 7 else b"CMD:sleep 60", next_beacon, beacon_ua)
    if n % 6 == 3:                                                     # the user keeps browsing
        d, size = random.choice(normal)
        https_visit(d, size, dns_lookup(d, next_beacon + random.uniform(10, 40)))
    next_beacon += 60 + random.uniform(-1.5, 1.5)

packets.sort(key=lambda p: p.time)
OUT.parent.mkdir(exist_ok=True)
wrpcap(str(OUT), packets)
print(f"Wrote {len(packets)} packets to {OUT}")
