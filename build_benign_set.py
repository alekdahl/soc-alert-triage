import csv
import pandas as pd

SEED = 42
LABELS = "labels/labels.csv"

df = pd.read_json("data/benign_alerts.jsonl", lines=True)

# Én tilfeldig alarm per regel, så vi får variasjon i stedet for 50 x "Proc Access"
sample = (
    df.groupby("RuleTitle", group_keys=False)
    .sample(n=1, random_state=SEED)
    .sort_values("RuleTitle")
    .reset_index(drop=True)
)

# Egne ID-er (B = baseline), så de ikke blandes med A001-A100
sample.insert(0, "alert_id", [f"B{i:03d}" for i in range(1, len(sample) + 1)])
sample["tactic"] = "Baseline (ren maskin)"

sample.to_json("data/eval_set_benign.jsonl", orient="records", lines=True, force_ascii=False)

# Legg til fasit: alle er harmløse, fordi maskinen er ren (men bare hvis de ikke er lagt til fra før)
existing = set(pd.read_csv(LABELS)["alert_id"])
new_rows = [
    [alert_id, "benign", "Ren baseline-maskin (Nextron evtx-baseline)"]
    for alert_id in sample["alert_id"]
    if alert_id not in existing
]
with open(LABELS, "a", newline="", encoding="utf-8") as f:
    csv.writer(f).writerows(new_rows)

print(f"Harmløse alarmer valgt ut: {len(sample)}")
print(f"Nye linjer i fasiten:      {len(new_rows)}\n")
print(sample["Level"].value_counts())
