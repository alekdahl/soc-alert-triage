import json
import sys
from typing import Literal

import anthropic
from dotenv import load_dotenv
from pydantic import BaseModel, Field

load_dotenv()
client = anthropic.Anthropic()

MODEL = "claude-haiku-5-5"

Tactic = Literal[
    "Reconnaissance", "Resource Development", "Initial Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
    "Discovery", "Lateral Movement", "Collection", "Command and Control",
    "Exfiltration", "Impact", "None",
]


# Svarformatet Claude MÅ følge
class Triage(BaseModel):
    verdict: Literal["malicious", "benign"]
    confidence: Literal["low", "medium", "high"]
    severity: Literal["informational", "low", "medium", "high", "critical"]
    tactic: Tactic
    technique_id: str = Field(description="MITRE ATT&CK technique ID, e.g. T1003.001. Empty string if benign.")
    summary: str = Field(description="One or two sentences for the analyst.")
    next_steps: list[str] = Field(description="Concrete next investigation steps.")


SYSTEM_PROMPT = """You are an experienced SOC analyst triaging alerts from a Windows environment.
Each alert was produced by a Sigma rule that matched a Windows event log entry.
Many alerts are false positives caused by normal system or user activity.

Decide whether the activity in the alert is malicious or benign, based only on the evidence in the event.
The rule title and level describe what the rule looks for, not whether this specific event is an attack.
For malicious activity, give the most relevant MITRE ATT&CK tactic and technique.
Keep the summary short and factual, and suggest concrete next investigation steps."""

# Felt som ville avslørt fasiten. Disse får Claude ikke se.
HIDDEN_FIELDS = {"alert_id", "tactic", "EvtxFile", "RuleFile", "RuleID", "RecordID", "OtherTags", "Timestamp"}


def alert_to_text(alert):
    visible = {key: value for key, value in alert.items() if key not in HIDDEN_FIELDS}
    return json.dumps(visible, indent=2, ensure_ascii=False)


def load_alerts():
    alerts = {}
    for path in ["data/eval_set.jsonl", "data/eval_set_benign.jsonl"]:
        with open(path, encoding="utf-8") as f:
            for line in f:
                alert = json.loads(line)
                alerts[alert["alert_id"]] = alert
    return alerts


def triage(alert, model=MODEL):
    return client.messages.parse(
        model=model,
        max_tokens=8000,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": "Triage this alert:\n\n" + alert_to_text(alert)}],
        output_format=Triage,
    )


if __name__ == "__main__":
    alert_id = sys.argv[1]
    alert = load_alerts()[alert_id]

    print("=== Dette ser Claude ===")
    print(alert_to_text(alert))

    response = triage(alert)

    print("\n=== Claudes vurdering ===")
    if response.parsed_output is None:
        print(f"Ingen gyldig vurdering (stop_reason: {response.stop_reason})")
    else:
        print(response.parsed_output.model_dump_json(indent=2))
    print(f"\nTokens: {response.usage.input_tokens} inn, {response.usage.output_tokens} ut")
