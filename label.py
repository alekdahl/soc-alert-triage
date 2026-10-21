import csv
import json
import os

EVAL_SET = "data/eval_set.jsonl"
LABELS = "labels/labels.csv"
CHOICES = {"m": "malicious", "b": "benign", "u": "unsure"}

os.makedirs("labels", exist_ok=True)

# Les evalueringssettet
with open(EVAL_SET, encoding="utf-8") as f:
    alerts = [json.loads(line) for line in f]

# Finn ut hvilke alarmer som allerede er merket, så vi kan fortsette der vi slapp
done = set()
if os.path.exists(LABELS):
    with open(LABELS, encoding="utf-8") as f:
        done = {row["alert_id"] for row in csv.DictReader(f)}

new_file = not os.path.exists(LABELS)
with open(LABELS, "a", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    if new_file:
        writer.writerow(["alert_id", "label", "comment"])

    for alert in alerts:
        if alert["alert_id"] in done:
            continue

        print("\n" + "=" * 70)
        print(f"{alert['alert_id']}   ({len(done) + 1}/{len(alerts)})")
        print(f"Taktikk (fra mappe): {alert['tactic']}")
        print(f"Loggfil:             {os.path.basename(alert['EvtxFile'])}")
        print(f"Regel:               {alert['RuleTitle']}  [{alert['Level']}]")
        print(f"Maskin:              {alert['Computer']}   EventID {alert['EventID']}")
        print("-" * 70)
        for key, value in alert["AllFieldInfo"].items():
            text = str(value)
            if text and text != "-":
                print(f"  {key}: {text[:200]}")

        answer = ""
        while answer not in CHOICES and answer != "q":
            answer = input("\n[m] ondsinnet  [b] harmløs  [u] usikker  [q] avslutt: ").strip().lower()
        if answer == "q":
            break

        comment = input("Kort begrunnelse (valgfri, Enter for å hoppe over): ").strip()
        writer.writerow([alert["alert_id"], CHOICES[answer], comment])
        f.flush()
        done.add(alert["alert_id"])

print(f"\nMerket: {len(done)}/{len(alerts)}. Svarene ligger i {LABELS}.")
