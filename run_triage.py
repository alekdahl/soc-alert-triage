import json
import os
import sys
import time

from triage import load_alerts, triage

model = sys.argv[1] if len(sys.argv) > 1 else "claude-haiku-5-5"
out_path = f"results/{model}.jsonl"
os.makedirs("results", exist_ok=True)

# Hopp over alarmer som allerede er vurdert (så vi kan fortsette der vi slapp)
done = set()
if os.path.exists(out_path):
    with open(out_path, encoding="utf-8") as f:
        done = {json.loads(line)["alert_id"] for line in f}

alerts = load_alerts()
todo = [alert for alert_id, alert in alerts.items() if alert_id not in done]
print(f"Modell: {model} | ferdig fra før: {len(done)} | gjenstår: {len(todo)}\n")

with open(out_path, "a", encoding="utf-8") as f:
    for i, alert in enumerate(todo, 1):
        start = time.time()
        try:
            response = triage(alert, model=model)
        except Exception as e:
            print(f"[{i}/{len(todo)}] {alert['alert_id']}: FEIL ({type(e).__name__}): prøves igjen ved neste kjøring")
            continue

        parsed = response.parsed_output
        record = {
            "alert_id": alert["alert_id"],
            "model": model,
            "seconds": round(time.time() - start, 2),
            "stop_reason": response.stop_reason,
            "input_tokens": response.usage.input_tokens,
            "output_tokens": response.usage.output_tokens,
            "result": parsed.model_dump() if parsed else None,
        }
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
        f.flush()

        verdict = parsed.verdict if parsed else f"ingen vurdering ({response.stop_reason})"
        print(f"[{i}/{len(todo)}] {alert['alert_id']}: {verdict}")

print(f"\nFerdig. Svarene ligger i {out_path}")
