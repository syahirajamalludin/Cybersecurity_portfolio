"""
DDoS detection: a simple rate rule vs a machine-learning model.

Usage:
  python detect_ddos.py                       # uses data/flows.csv (synthetic)
  python detect_ddos.py path/to/CIC_file.csv  # works on real CIC-DDoS2019 CSVs too

Steps:
  1. Load + clean flow data
  2. Baseline: the kind of rule a firewall uses ("too many packets per second = attack")
  3. Machine learning: Random Forest that learns from 10 flow features
  4. Compare both, explain which features matter, save charts
"""
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, recall_score
from sklearn.model_selection import train_test_split

HERE = Path(__file__).parent
CSV = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "data" / "flows.csv"
RATE_RULE_PPS = 10_000      # baseline: flag flows faster than this (packets per second)
FEATURES = ["Protocol", "Destination Port", "Flow Duration", "Total Fwd Packets",
            "Total Backward Packets", "Total Length of Fwd Packets", "Fwd Packet Length Mean",
            "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "SYN Flag Count", "ACK Flag Count"]

# ---------- 1. Load + clean ----------
df = pd.read_csv(CSV, low_memory=False)
df.columns = df.columns.str.strip()             # real CIC files have " Label" with a space
df = df[FEATURES + ["Label"]].replace([np.inf, -np.inf], np.nan).dropna()
df["is_attack"] = (df["Label"] != "BENIGN").astype(int)
print(f"Flows: {len(df):,}   attacks: {df.is_attack.mean():.0%}")
print(df["Label"].value_counts().to_string(), "\n")

train, test = train_test_split(df, test_size=0.3, random_state=42, stratify=df["Label"])

# ---------- 2. Baseline rule ----------
test = test.copy()
test["rule_pred"] = (test["Flow Packets/s"] > RATE_RULE_PPS).astype(int)

# ---------- 3. Machine learning ----------
model = RandomForestClassifier(n_estimators=200, max_depth=12, random_state=42, n_jobs=-1)
model.fit(train[FEATURES], train["Label"])
test["ml_label"] = model.predict(test[FEATURES])
test["ml_pred"] = (test["ml_label"] != "BENIGN").astype(int)


# ---------- 4. Compare ----------
def scores(pred):
    tn, fp, fn, tp = confusion_matrix(test.is_attack, pred).ravel()
    return {"attacks caught": f"{tp / (tp + fn):.1%}", "attacks missed": f"{fn:,}",
            "false alarms": f"{fp:,}", "false alarm rate": f"{fp / (fp + tn):.1%}"}


compare = pd.DataFrame({"Rate rule": scores(test.rule_pred), "Random Forest": scores(test.ml_pred)})
print("=== Attack vs normal (test set) ===")
print(compare.to_string(), "\n")

print("=== Which attack type? (Random Forest) ===")
print(classification_report(test.Label, test.ml_label, digits=3))

print("=== Caught by each method, per attack type ===")
per_type = pd.DataFrame({
    "Rate rule": test[test.is_attack == 1].groupby("Label").apply(
        lambda g: recall_score(g.is_attack, g.rule_pred, zero_division=0), include_groups=False),
    "Random Forest": test[test.is_attack == 1].groupby("Label").apply(
        lambda g: recall_score(g.is_attack, g.ml_pred, zero_division=0), include_groups=False),
})
print(per_type.to_string(float_format="{:.1%}".format), "\n")

importance = pd.Series(model.feature_importances_, index=FEATURES).sort_values()
print("=== Top 5 features ===")
print(importance.tail(5)[::-1].to_string(float_format="{:.3f}".format))

# ---------- 5. Charts ----------
(HERE / "img").mkdir(exist_ok=True)
plt.rcParams.update({"axes.spines.top": False, "axes.spines.right": False})
GREY, BLUE = "#8a8f98", "#4a7bb7"

fig, ax = plt.subplots(figsize=(8, 3.6))
x = np.arange(len(per_type))
ax.bar(x - 0.2, per_type["Rate rule"] * 100, 0.4, label="Rate rule", color=GREY)
ax.bar(x + 0.2, per_type["Random Forest"] * 100, 0.4, label="Random Forest", color=BLUE)
for i, (r, m) in enumerate(per_type.values):
    ax.text(i - 0.2, r * 100 + 1.5, f"{r:.0%}", ha="center", fontsize=9)
    ax.text(i + 0.2, m * 100 + 1.5, f"{m:.0%}", ha="center", fontsize=9)
ax.set_xticks(x, per_type.index)
ax.set_ylabel("% of attack flows caught")
ax.set_ylim(0, 128)
ax.set_title("A simple 'too fast = attack' rule misses whole attack types")
ax.legend(frameon=False, loc="upper center", ncol=2)
fig.tight_layout()
fig.savefig(HERE / "img" / "rule_vs_ml.png", dpi=150)

fig, ax = plt.subplots(figsize=(7, 4))
ax.barh(importance.index, importance.values, color=BLUE)
ax.set_title("What the model looks at most (feature importance)")
fig.tight_layout()
fig.savefig(HERE / "img" / "feature_importance.png", dpi=150)

labels = sorted(df.Label.unique(), key=lambda l: (l != "BENIGN", l))
cm = confusion_matrix(test.Label, test.ml_label, labels=labels)
fig, ax = plt.subplots(figsize=(5.5, 4.5))
ax.imshow(cm, cmap="Blues")
for i in range(len(labels)):
    for j in range(len(labels)):
        ax.text(j, i, cm[i, j], ha="center", va="center",
                color="white" if cm[i, j] > cm.max() / 2 else "black")
ax.set_xticks(range(len(labels)), labels, rotation=30)
ax.set_yticks(range(len(labels)), labels)
ax.set_xlabel("Model said")
ax.set_ylabel("Actually was")
ax.set_title("Confusion matrix (test set)")
for s in ax.spines.values():
    s.set_visible(False)
fig.tight_layout()
fig.savefig(HERE / "img" / "confusion_matrix.png", dpi=150)
print("\nCharts saved to img/")
