import pandas as pd

# Les alle alarmene (én JSON-linje per alarm) inn i en tabell
df = pd.read_json("data/alerts.jsonl", lines=True)

# Hent ATT&CK-taktikken fra mappenavnet i filstien
# "../../data/evtx/Credential Access/fil.evtx" -> "Credential Access"
df["tactic"] = (
    df["EvtxFile"]
    .str.replace("../../data/evtx/", "", regex=False)
    .str.split("/")
    .str[0]
)

print(f"Antall alarmer: {len(df)}\n")

print("Alarmer per alvorlighetsnivå:")
print(df["Level"].value_counts(), "\n")

print("Alarmer per ATT&CK-taktikk (mappe):")
print(df["tactic"].value_counts(), "\n")

print("De 10 vanligste reglene:")
print(df["RuleTitle"].value_counts().head(10), "\n")

# Samme regel i samme fil = egentlig samme alarm gjentatt
unique = df.drop_duplicates(subset=["EvtxFile", "RuleTitle"])
print(f"Unike alarmer (fil + regel): {len(unique)}")
