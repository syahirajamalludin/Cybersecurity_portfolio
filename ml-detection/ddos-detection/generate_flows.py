"""
Creates SYNTHETIC network-flow data that copies the column names and the
general behaviour of the public CIC-DDoS2019 dataset (made with CICFlowMeter).

You don't need to run this — data/flows.csv is already included.
Want real data? Download CIC-DDoS2019 from the University of New Brunswick
(https://www.unb.ca/cic/datasets/ddos-2019.html) and point detect_ddos.py at it.

One row = one "flow" = all packets between the same 2 IPs/ports in one conversation.
"""
from pathlib import Path

import numpy as np
import pandas as pd

rng = np.random.default_rng(7)
OUT = Path(__file__).parent / "data" / "flows.csv"


def flows(n, label, proto, dport, dur_ms, fwd_pkts, bwd_pkts, fwd_len, syn, ack):
    """Each argument is (low, high) — values are drawn randomly inside that range."""
    u = lambda lo_hi, size=n: rng.uniform(*lo_hi, size)
    duration_us = u(dur_ms) * 1000
    f_pk = np.maximum(1, u(fwd_pkts).round())
    b_pk = np.maximum(0, u(bwd_pkts).round())
    f_len = u(fwd_len)
    total_bytes = f_pk * f_len
    secs = np.maximum(duration_us / 1e6, 1e-6)
    return pd.DataFrame({
        "Protocol": proto,
        "Destination Port": rng.choice(dport, n),
        "Flow Duration": duration_us.round(),
        "Total Fwd Packets": f_pk,
        "Total Backward Packets": b_pk,
        "Total Length of Fwd Packets": total_bytes.round(),
        "Fwd Packet Length Mean": f_len.round(1),
        "Flow Bytes/s": (total_bytes / secs).round(1),
        "Flow Packets/s": ((f_pk + b_pk) / secs).round(1),
        "Flow IAT Mean": (duration_us / np.maximum(f_pk + b_pk - 1, 1)).round(1),
        "SYN Flag Count": (rng.random(n) < syn).astype(int),
        "ACK Flag Count": (rng.random(n) < ack).astype(int),
        "Label": label,
    })


parts = [
    # Normal web, DNS and app traffic: longer, two-way, mixed sizes
    flows(5000, "BENIGN", 6, [443, 80, 8080], (50, 30_000), (3, 60), (2, 80), (60, 1200), 0.9, 0.98),
    flows(1500, "BENIGN", 17, [53, 123], (1, 200), (1, 2), (1, 2), (40, 120), 0, 0),
    # Busy but normal: video streams and backups — fast, but legitimate (two-way)
    flows(600, "BENIGN", 6, [443], (5, 200), (50, 300), (40, 300), (900, 1450), 0.9, 1.0),
    # SYN flood: thousands of tiny half-open connections, no reply, SYN flag set
    flows(2500, "Syn", 6, [80, 443], (0.01, 5), (1, 3), (0, 1), (0, 6), 1.0, 0.05),
    # UDP flood: lots of UDP packets fired as fast as possible at random-ish ports
    flows(2000, "UDP", 17, list(range(1000, 65000, 997)), (0.01, 20), (2, 400), (0, 0), (300, 1450), 0, 0),
    # DNS reflection (DrDoS_DNS): big DNS answers arriving from port 53, one direction
    flows(2000, "DrDoS_DNS", 17, [53], (0.01, 50), (2, 200), (0, 0), (1000, 1480), 0, 0),
]
# Hard cases so it isn't too easy: "low and slow" attacks that look a lot like normal traffic
parts += [
    flows(300, "Syn", 6, [443], (50, 3000), (2, 6), (1, 4), (0, 200), 1.0, 0.8),
    flows(300, "UDP", 17, [53, 123], (1, 200), (1, 2), (0, 2), (40, 160), 0, 0),
    flows(200, "DrDoS_DNS", 17, [53], (1, 200), (1, 2), (0, 1), (60, 300), 0, 0),
]
df = pd.concat(parts, ignore_index=True).sample(frac=1, random_state=7).reset_index(drop=True)
OUT.parent.mkdir(exist_ok=True)
df.to_csv(OUT, index=False)
print(f"Wrote {len(df):,} flows to {OUT}")
print(df["Label"].value_counts().to_string())
