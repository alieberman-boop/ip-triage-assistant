"""
IP Triage Assistant — local build.

Deliberately written the way a citizen developer would write it: plain SDK calls,
no telemetry, no logging framework, nobody told the governance platform it exists.
That is the point. Visibility has to be retrofitted from outside.

Two runtime modes, one switch (USE_LLM):
  - USE_LLM=true  -> the verdict comes from the model. Spends AI credits on the
                     key; a gateway can capture the call. Visible to governance.
  - USE_LLM=false -> the verdict comes from a deterministic rule over the
                     VirusTotal numbers. No model call, no AI spend, nothing on
                     any AI channel. This is the deterministic-automation case:
                     identical to the user, invisible to spend-based governance.
"""

import os
import requests
from flask import Flask, render_template, request, jsonify
from anthropic import Anthropic

app = Flask(__name__)

# The SDK reads ANTHROPIC_API_KEY and ANTHROPIC_BASE_URL from the environment.
# Note there is no base_url argument here. Pointing this app at a gateway is a
# deployment concern, not a code change -- which is the whole retrofit thesis.
client = Anthropic()

VT_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
MODEL = os.environ.get("MODEL", "claude-haiku-4-5")
USE_LLM = os.environ.get("USE_LLM", "true").strip().lower() not in ("false", "0", "no")


def enrich_ip(ip):
    """VirusTotal reputation for an IP address."""
    if not VT_KEY:
        return {"error": "VIRUSTOTAL_API_KEY not set", "malicious": None}
    r = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": VT_KEY},
        timeout=20,
    )
    if r.status_code != 200:
        return {"error": f"VirusTotal returned {r.status_code}", "malicious": None}
    attrs = r.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "country": attrs.get("country"),
        "owner": attrs.get("as_owner"),
        "reputation": attrs.get("reputation"),
    }


def verdict_deterministic(ip, vt):
    """A one-line verdict from a fixed rule -- no model, no AI spend."""
    if vt.get("error"):
        return f"Could not assess {ip}: {vt['error']}."
    mal = vt.get("malicious") or 0
    susp = vt.get("suspicious") or 0
    if mal >= 1:
        return f"Block {ip}: {mal} engines flag it malicious ({susp} suspicious)."
    if susp >= 1:
        return f"Investigate {ip}: {susp} engines flag it suspicious, none malicious."
    return f"No action needed for {ip}: no engines flag it malicious or suspicious."


def verdict_llm(ip, vt):
    """A one-line verdict from the model. This is the only AI spend in the app."""
    prompt = (
        "You are triaging a security alert. Given this VirusTotal reputation "
        f"for IP {ip}:\n{vt}\n\n"
        "Respond with exactly one sentence telling the analyst what to do about "
        "this IP. No preamble, no labels."
    )
    msg = client.messages.create(
        model=MODEL,
        max_tokens=150,
        messages=[{"role": "user", "content": prompt}],
    )
    text = msg.content[0].text.strip()
    return {
        "verdict": text,
        "mode": "llm",
        "usage": {
            "input_tokens": msg.usage.input_tokens,
            "output_tokens": msg.usage.output_tokens,
        },
    }


@app.route("/")
def index():
    return render_template("index.html", use_llm=USE_LLM)


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.json or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "no ip supplied"}), 400
    # The on-screen toggle sends use_llm per request; env USE_LLM is the default
    # when the caller doesn't specify (e.g. a headless/scheduled run).
    use_llm = data.get("use_llm")
    if use_llm is None:
        use_llm = USE_LLM
    vt = enrich_ip(ip)
    if use_llm:
        try:
            advice = verdict_llm(ip, vt)
        except Exception as exc:
            return jsonify({"error": f"model call failed: {exc}", "virustotal": vt}), 502
    else:
        advice = {"verdict": verdict_deterministic(ip, vt), "mode": "deterministic"}
    return jsonify({"ip": ip, "virustotal": vt, "advice": advice})


if __name__ == "__main__":
    base = os.environ.get("ANTHROPIC_BASE_URL")
    print(f"  mode           : {'LLM (spends AI credits)' if USE_LLM else 'deterministic (no AI spend)'}")
    print(f"  model endpoint : {base or 'https://api.anthropic.com (direct)'}")
    print("  listening on   : http://127.0.0.1:5001")
    app.run(port=5001, debug=False)
