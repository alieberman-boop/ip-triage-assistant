# IP Triage Assistant

Enter an IP address, get its VirusTotal reputation, and a one-line triage verdict.

A small internal tool: paste an IP from an alert, see how many engines flag it,
and get a plain-English "block / investigate / no action" call.

## How it works

1. Look up the IP on [VirusTotal](https://www.virustotal.com) (reputation, country, owner).
2. Turn those numbers into a one-sentence verdict.

The verdict has two modes, controlled by `USE_LLM`:

- `USE_LLM=true` — the verdict comes from Claude (`claude-haiku-4-5`) via the
  Anthropic SDK.
- `USE_LLM=false` — the verdict comes from a fixed rule over the VirusTotal
  numbers. No model call.

## Run it

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # then fill in your keys
python app.py             # http://127.0.0.1:5001
```

## Config

See `.env.example`. You need an Anthropic API key and a (free-tier) VirusTotal
key. Nothing is committed — `.env` is gitignored.
