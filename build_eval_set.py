import pandas as pd

SEED = 42           # fast "tilfeldighet", så du får samme utvalg hver gang
SAMPLE_SIZE = 100   # omtrent så mange alarmer vi vil merke

df = pd.read_json("data/alerts.jsonl", lines=True)

# Taktikk fra mappenavnet (samme som i explore.py)
df["tactic"] = (
    df["EvtxFile"]
    .str.replace("../../data/evtx/", "", regex=False)
    .str.split("/")
    .str[0]
)

# Behold bare mapper som faktisk er ATT&CK-taktikker
TACTICS = [
    "Credential Access", "Defense Evasion", "Discovery", "Execution",
    "Lateral Movement", "Persistence", "Privilege Escalation", "Command and Control",
]
df = df[df["tactic"].isin(TACTICS)]

# Fjern gjentakelser: én alarm per kombinasjon av fil og regel
unique = df.drop_duplicates(subset=["EvtxFile", "RuleTitle"]).copy()

# Stratifisert utvalg: samme andel fra hver taktikk
frac = SAMPLE_SIZE / len(unique)
sample = (
    unique.groupby("tactic", group_keys=False)
    .sample(frac=frac, random_state=SEED)
    .reset_index(drop=True)
)

# Gi hver alarm en fast ID vi kan henvise til senere
sample.insert(0, "alert_id", [f"A{i:03d}" for i in range(1, len(sample) + 1)])

sample.to_json("data/eval_set.jsonl", orient="records", lines=True, force_ascii=False)

print(f"Unike alarmer i taktikk-mapper: {len(unique)}")
print(f"Evalueringssett: {len(sample)} alarmer\n")
print(sample["tactic"].value_counts(), "\n")
print(sample["Level"].value_counts())
