from dotenv import load_dotenv
import anthropic

load_dotenv()                    # leser ANTHROPIC_API_KEY fra .env
client = anthropic.Anthropic()   # finner nøkkelen automatisk

response = client.messages.create(
    model="claude-haiku-5-5",    # billigste modell, perfekt under utvikling
    max_tokens=1024,             # maks lengde på svaret
    messages=[
        {"role": "user", "content": "Forklar i én setning hva en SOC-analytiker gjør."}
    ],
)

for block in response.content:
    if block.type == "text":
        print(block.text)

print(f"\nTokens brukt: {response.usage.input_tokens} inn, {response.usage.output_tokens} ut")
