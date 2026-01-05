import os

API_KEY = os.getenv("VT_API_KEY")

if not API_KEY:
    print("VirusTotal API key not found. Please set VT_API_KEY.")
    exit()

import email
from email import policy
import re
import json
import base64
import requests

# ---------------- CONFIG ----------------
   # keep secret, do not commit
EMAIL_FILE = "samples/sample-1.eml"
# --------------------------------------


# -------- Attachment Detection (SAFE) --------
attachments = []

with open(EMAIL_FILE, "r", encoding="utf-8", errors="ignore") as f:
    msg = email.message_from_file(f, policy=policy.default)

if msg.is_multipart():
    for part in msg.walk():
        filename = part.get_filename()
        if filename:
            attachments.append(filename)

if attachments:
    print("\nAttachments detected:")
    for a in attachments:
        print("-", a)
else:
    print("\nNo attachments detected")
# --------------------------------------------


# -------- URL Extraction --------
with open(EMAIL_FILE, "r", encoding="utf-8", errors="ignore") as f:
    content = f.read()

decoded_text = ""
base64_blocks = re.findall(r'(?:[A-Za-z0-9+/]{20,}={0,2})', content)

for block in base64_blocks:
    try:
        decoded = base64.b64decode(block)
        decoded_text += decoded.decode("utf-8", errors="ignore")
    except:
        pass

urls = list(set(re.findall(r'https?://[^\s"<>]+', decoded_text)))

print("\nExtracted URLs:")
for url in urls:
    print("-", url)
# --------------------------------------------


# -------- Phishing Type Classification --------
if urls and attachments:
    phishing_type = "Hybrid Phishing (URL + Attachment)"
elif urls:
    phishing_type = "URL-based Phishing"
elif attachments:
    phishing_type = "Attachment-based Phishing"
else:
    phishing_type = "Unknown / No IOC Found"

print("\nPhishing Type:", phishing_type)
# ---------------------------------------------


# -------- Select Phishing URL --------
phishing_urls = []

for url in urls:
    if "googleapis" in url or "gstatic" in url:
        continue
    phishing_urls.append(url)

phishing_url = phishing_urls[0] if phishing_urls else None

if phishing_url:
    print("\nSelected phishing URL:", phishing_url)
# -----------------------------------


# -------- VirusTotal Enrichment --------
stats = {}

if phishing_url:
    url_id = base64.urlsafe_b64encode(phishing_url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {"x-apikey": API_KEY}
    response = requests.get(vt_url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        print("\nVirusTotal Result:", stats)
    else:
        print("\nVirusTotal API error")
# -------------------------------------


# -------- Severity Automation --------
malicious = stats.get("malicious", 0)
suspicious = stats.get("suspicious", 0)

if malicious > 0:
    severity = "HIGH"
elif phishing_url:
    severity = "MEDIUM"
else:
    severity = "LOW"
# ------------------------------------


# -------- Final SOC Report --------
incident = {
    "email_file": EMAIL_FILE,
    "phishing_type": phishing_type,
    "attachments": attachments,
    "phishing_url": phishing_url,
    "virustotal": stats,
    "final_severity": severity
}

print("\nFINAL SOC DECISION")
print("Severity:", severity)

with open("final_incident_report.json", "w") as f:
    json.dump(incident, f, indent=4)

print("\nIncident report saved as final_incident_report.json")
# -----------------------------------
