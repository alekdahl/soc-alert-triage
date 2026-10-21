import json

import pandas as pd

MODELS = ["claude-haiku-5-5", "claude-sonnet-5-5"]
PRICE_PER_MTOK = {  # USD per million tokens (inn, ut)
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00),
}

labels = pd.read_csv("labels/labels.csv")

# Taktikk-fasit fra evalueringssettet (bare for angrepsalarmene)
tactics = {}
with open("data/eval_set.jsonl", encoding="utf-8") as f:
    for line in f:
        alert = json.loads(line)
        tactics[alert["alert_id"]] = alert["tactic"]
labels["true_tactic"] = labels["alert_id"].map(tactics)

summary, errors = [], []

for model in MODELS:
    res = pd.read_json(f"results/{model}.jsonl", lines=True)
    res["pred"] = res["result"].apply(lambda r: r["verdict"])
    res["pred_tactic"] = res["result"].apply(lambda r: r["tactic"])
    res["confidence"] = res["result"].apply(lambda r: r["confidence"])
    df = labels.merge(res, on="alert_id")

    sure = df[df["label"] != "unsure"]
    tp = ((sure.label == "malicious") & (sure.pred == "malicious")).sum()
    fn = ((sure.label == "malicious") & (sure.pred == "benign")).sum()
    tn = ((sure.label == "benign") & (sure.pred == "benign")).sum()
    fp = ((sure.label == "benign") & (sure.pred == "malicious")).sum()

    # Taktikk: bare ekte angrep som modellen også kalte ondsinnet
    hits = sure[(sure.label == "malicious") & (sure.pred == "malicious")]
    tactic_acc = (hits.pred_tactic == hits.true_tactic).mean()

    price_in, price_out = PRICE_PER_MTOK[model]
    cost = (res.input_tokens.sum() * price_in + res.output_tokens.sum() * price_out) / 1e6
    cost_per_alert = cost / len(res)

    summary.append({
        "Modell": model,
        "Oppdagede angrep": f"{tp}/{tp + fn} ({tp / (tp + fn):.0%})",
        "Oversette angrep": fn,
        "Avfeid støy": f"{tn}/{tn + fp} ({tn / (tn + fp):.0%})",
        "Falske eskaleringer": fp,
        "Presisjon": f"{tp / (tp + fp):.0%}",
        "Riktig taktikk": f"{tactic_acc:.0%}",
        "Sek/alarm": round(res.seconds.mean(), 1),
        "USD/alarm": round(cost_per_alert, 4),
        "USD per 10 000 alarmer": round(cost_per_alert * 10_000, 2),
    })

    wrong = sure[sure.label != sure.pred].copy()
    wrong["model"] = model
    errors.append(wrong[["model", "alert_id", "label", "pred", "confidence", "true_tactic"]])

    print(f"\n=== {model}: de {len(df[df.label == 'unsure'])} usikre alarmene ===")
    print(df[df.label == "unsure"][["alert_id", "pred", "confidence"]].to_string(index=False))

summary_df = pd.DataFrame(summary).set_index("Modell").T
errors_df = pd.concat(errors)

print("\n=== Resultater (uten usikre alarmer) ===")
print(summary_df.to_string())
print("\n=== Feil ===")
print(errors_df.to_string(index=False))

summary_df.to_csv("results/summary.csv")
errors_df.to_csv("results/errors.csv", index=False)
