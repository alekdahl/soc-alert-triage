import os

import matplotlib.pyplot as plt
import pandas as pd

MODELS = {"claude-haiku-5-5": "Haiku 5.5", "claude-sonnet-5-5": "Sonnet 5.5"}
COST_PER_10K = {"claude-haiku-5-5": 5.08, "claude-sonnet-5-5": 72.24}  # fra results/summary.csv

os.makedirs("figures", exist_ok=True)
labels = pd.read_csv("labels/labels.csv")
labels = labels[labels["label"] != "unsure"]

rates = {}
fig, axes = plt.subplots(1, 2, figsize=(10, 4.2))

for ax, (model, name) in zip(axes, MODELS.items()):
    res = pd.read_json(f"results/{model}.jsonl", lines=True)
    res["pred"] = res["result"].apply(lambda r: r["verdict"])
    df = labels.merge(res, on="alert_id")

    classes = ["malicious", "benign"]
    matrix = pd.crosstab(df["label"], df["pred"]).reindex(index=classes, columns=classes, fill_value=0)

    ax.imshow(matrix.values, cmap="Blues")
    for i in range(2):
        for j in range(2):
            value = matrix.values[i, j]
            ax.text(j, i, value, ha="center", va="center", fontsize=16,
                    color="white" if value > matrix.values.max() / 2 else "black")
    ax.set_xticks([0, 1], ["Malicious", "Benign"])
    ax.set_yticks([0, 1], ["Malicious", "Benign"])
    ax.set_xlabel("Model verdict")
    ax.set_ylabel("Ground truth")
    ax.set_title(name)

    tp, fn = matrix.loc["malicious", "malicious"], matrix.loc["malicious", "benign"]
    tn, fp = matrix.loc["benign", "benign"], matrix.loc["benign", "malicious"]
    rates[name] = {"Attacks detected": tp / (tp + fn), "Noise dismissed": tn / (tn + fp)}

fig.suptitle("Alert triage vs. ground truth (n = 150, unsure excluded)")
fig.tight_layout()
fig.savefig("figures/confusion_matrices.png", dpi=150)

# Sammenligning av modellene
rates_df = pd.DataFrame(rates)
ax = rates_df.plot.bar(figsize=(8, 4.5), rot=0, color=["#9ecae1", "#3182bd"], width=0.7)
for container in ax.containers:
    ax.bar_label(container, labels=[f"{v:.0%}" for v in container.datavalues], padding=3)
ax.set_ylim(0, 1.1)
ax.set_ylabel("Share of alerts")
ax.legend([f"{name} (${COST_PER_10K[model]:.0f} per 10k alerts)" for model, name in MODELS.items()],
          loc="lower right")
ax.set_title("Detection vs. noise reduction, and cost")
plt.tight_layout()
plt.savefig("figures/model_comparison.png", dpi=150)

print("Lagret: figures/confusion_matrices.png og figures/model_comparison.png")
