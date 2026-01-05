
# Phishing Email Automation – SOC Project

## Overview
This project demonstrates a **SOC-style phishing email automation** workflow using Python.  
It simulates how a Security Operations Center (SOC) analyst automates phishing triage to reduce manual investigation time.

The automation processes real phishing email files (`.eml`), extracts indicators of compromise (IOCs), enriches them with threat intelligence, classifies phishing type, assigns severity, and generates an incident report.

---

## Key Features
- Analyzes real phishing email files (`.eml`)
- Safely detects presence of email attachments
- Extracts phishing URL IOCs (handles base64-encoded content)
- Filters legitimate vs suspicious URLs
- Enriches URLs using VirusTotal API
- Classifies phishing type:
  - URL-based phishing
  - Attachment-based phishing
  - Hybrid phishing
- Applies rule-based severity classification (High / Medium / Low)
- Generates a SOC-style incident report in JSON format

---

## Technologies Used
- Python
- VirusTotal API
- Email parsing (`email` library)
- Regular Expressions
- Threat Intelligence enrichment

---

## Project Workflow
1. Read phishing email (`.eml`)
2. Detect presence of attachments
3. Decode and extract URL IOCs
4. Classify phishing type
5. Enrich phishing URL using VirusTotal
6. Assign severity based on detections and context
7. Generate structured incident report

---

## Configuration (Important)

This project uses **environment variables** to securely handle the VirusTotal API key.

### Set API Key (Windows – PowerShell)
```powershell
setx VT_API_KEY "your_virustotal_api_key_here"
