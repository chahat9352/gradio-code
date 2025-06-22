import gradio as gr
import openai
import requests

openai.api_key = "AIzaSyCqkdG3FZAl5H9YJNi7nIM-Skt9Bq4P4Ao"
VIRUSTOTAL_API_KEY = "AIzaSyCqkdG3FZAl5H9YJNi7nIM-Skt9Bq4P4Ao"

BANNED_LIST = ["com.spyware.app", "http://phishingsite.com", "keylogger.com"]

SUSPICIOUS_KEYWORDS = [
    "spy", "steal", "keylogger", "phish", "malware",
    "hacker", "track", "logger", "rootkit", "sniffer"
]

def is_https(entry):
    return entry.lower().startswith("https://")

def is_banned(entry):
    return entry.lower() in BANNED_LIST

def keyword_analysis(entry):
    return any(keyword in entry.lower() for keyword in SUSPICIOUS_KEYWORDS)

def virus_total_scan(entry):
    url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    data = {"url": entry}

    try:
        post_resp = requests.post(url, headers=headers, data=data)
        if post_resp.status_code != 200:
            return "Virus scan failed"
        scan_id = post_resp.json()["data"]["id"]

        report_url = f"https://www.virustotal.com/api/v3/analyses/{scan_id}"
        result = requests.get(report_url, headers=headers).json()
        stats = result["data"]["attributes"]["stats"]
        if stats["malicious"] > 0:
            return f"⚠️ Malicious ({stats['malicious']} engines)"
        elif stats["suspicious"] > 0:
            return f"⚠️ Suspicious ({stats['suspicious']} engines)"
        else:
            return "✅ Harmless"
    except Exception as e:
        return f"VirusTotal error: {e}"

def llm_analysis(entry):
    prompt = f"""Classify the following app or link as 'Safe' or 'Suspicious'. Explain why:
    
    Input: {entry}
    
    Output:"""

    try:
        response = openai.Completion.create(
            engine="text-davinci-003",
            prompt=prompt,
            max_tokens=60,
            temperature=0.3
        )
        return response.choices[0].text.strip()
    except Exception as e:
        return f"LLM error: {e}"

def analyze_apps_links(input_text, access_key=""):
    VALID_KEYS = ["abc123", "test456"]
    if access_key.strip() not in VALID_KEYS:
        return "❌ Access Denied. Please enter a valid access key after payment."

    entries = [e.strip() for e in input_text.split(",") if e.strip()]
    results = []

    for entry in entries:
        if is_banned(entry):
            results.append(f"{entry} → ❌ BANNED\nExplanation: Blocked by policy.")
            continue

        https_status = "✅ HTTPS" if is_https(entry) else "❌ Not using HTTPS"
        keyword_flag = keyword_analysis(entry)
        llm_result = llm_analysis(entry)
        vt_result = virus_total_scan(entry)

        combined_label = "⚠️ Suspicious" if "suspicious" in llm_result.lower() or keyword_flag else "✅ Safe"
        results.append(
            f"{entry} → {combined_label}\n"
            f"- HTTPS Check: {https_status}\n"
            f"- VirusTotal: {vt_result}\n"
            f"- AI Verdict: {llm_result}"
        )

    return "\n\n".join(results)

interface = gr.Interface(
    fn=analyze_apps_links,
    inputs=[
        gr.Textbox(label="Enter apps or URLs (comma-separated)"),
        gr.Textbox(label="Enter your access key")
    ],
    outputs=gr.Textbox(label="Scan Results"),
    title="🛡️ AI + Virus Threat Scanner",
    description="Advanced scanner combining OpenAI, VirusTotal, HTTPS check, and banned app detection. Paid access required.",
    examples=[
        ["http://phishingsite.com, com.spy.app", "abc123"],
        ["https://www.google.com", "test456"]
    ]
)

if __name__ == "__main__":
    interface.launch()
