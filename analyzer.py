import email
import sys
import argparse
import json
import re
from urllib.parse import urlparse
from difflib import SequenceMatcher
from collections import defaultdict

# ANSI Color Codes
COLORS = {
    "HEADER": "\033[95m", "BLUE": "\033[94m", "CYAN": "\033[96m",
    "GREEN": "\033[92m", "WARNING": "\033[93m", "FAIL": "\033[91m",
    "BOLD": "\033[1m", "ENDC": "\033[0m"
}

# Trusted domains for typosquatting checks (Add your org's domains here)
TRUSTED_DOMAINS = ["microsoft.com", "google.com", "amazon.com", "lanvaus.com"]

def parse_email(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        msg = email.message_from_file(f)
    return msg

def extract_urls(msg):
    urls = set()
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/html" or part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    text = payload.decode("utf-8", errors="ignore")
                    urls.update(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            text = payload.decode("utf-8", errors="ignore")
            urls.update(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text))
    return urls

def check_typosquatting(domain):
    for trusted in TRUSTED_DOMAINS:
        ratio = SequenceMatcher(None, domain.lower(), trusted.lower()).ratio()
        if 0.75 < ratio < 1.0:
            return True, trusted
    return False, None

def analyze_headers(msg):
    report = {
        "from": msg.get("From", "Unknown"),
        "to": msg.get("To", "Unknown"),
        "subject": msg.get("Subject", "Unknown"),
        "return_path": msg.get("Return-Path", "Unknown"),
        "spf": msg.get("Received-SPF", "Not Found"),
        "dkim": "Pass" if msg.get("DKIM-Signature") else "Fail/Missing",
        "dmarc": "Pass" if "dmarc=pass" in (msg.get("Authentication-Results") or "").lower() else "Fail/Missing",
        "urls": [],
        "risk_score": 0,
        "flags": []
    }

    # Header Analysis
    if "fail" in report["spf"].lower() or "none" in report["spf"].lower():
        report["risk_score"] += 20
        report["flags"].append("SPF Check Failed")
    if report["dkim"] != "Pass":
        report["risk_score"] += 20
        report["flags"].append("DKIM Missing/Failed")
    if report["dmarc"] != "Pass":
        report["risk_score"] += 20
        report["flags"].append("DMARC Check Failed")
    
    if report["from"] != report["return_path"] and report["return_path"] != "Unknown":
        report["risk_score"] += 15
        report["flags"].append("From and Return-Path Mismatch")

    # URL Analysis
    urls = extract_urls(msg)
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc.replace("www.", "")
        is_squatted, trusted_domain = check_typosquatting(domain)
        
        url_report = {"url": url, "domain": domain, "typosquatting": False}
        
        if is_squatted:
            url_report["typosquatting"] = True
            url_report["target"] = trusted_domain
            report["risk_score"] += 25
            report["flags"].append(f"Typosquatting detected: {domain} mimics {trusted_domain}")
        
        if parsed.scheme == "http":
            report["risk_score"] += 5
            report["flags"].append(f"Insecure HTTP URL found: {url}")
            
        report["urls"].append(url_report)

    report["risk_score"] = min(report["risk_score"], 100)
    return report

def print_report(report):
    print(f"\n{COLORS['HEADER']}{COLORS['BOLD']}️  PHISH-GUARD ANALYSIS REPORT{COLORS['ENDC']}\n")
    print(f"{COLORS['BLUE']}Subject: {report['subject']}{COLORS['ENDC']}")
    print(f"{COLORS['BLUE']}From: {report['from']}{COLORS['ENDC']}")
    print(f"{COLORS['BLUE']}Return-Path: {report['return_path']}{COLORS['ENDC']}\n")
    
    print(f"{COLORS['BOLD']}Authentication Results:{COLORS['ENDC']}")
    print(f"  SPF:   {report['spf']}")
    print(f"  DKIM:  {report['dkim']}")
    print(f"  DMARC: {report['dmarc']}\n")

    if report["flags"]:
        print(f"{COLORS['FAIL']}{COLORS['BOLD']}⚠️  Security Flags ({len(report['flags'])}):{COLORS['ENDC']}")
        for flag in report["flags"]:
            print(f"  -> {COLORS['WARNING']}{flag}{COLORS['ENDC']}")
    else:
        print(f"{COLORS['GREEN']}✅ No obvious header anomalies detected.{COLORS['ENDC']}")

    print(f"\n{COLORS['BOLD']}Extracted URLs ({len(report['urls'])}):{COLORS['ENDC']}")
    for u in report["urls"]:
        squatted = f" {COLORS['FAIL']}(MIMICS {u['target']}){COLORS['ENDC']}" if u["typosquatting"] else ""
        print(f"  -> {u['url']}{squatted}")

    print(f"\n{COLORS['BOLD']}Final Phishing Probability Score: {COLORS['FAIL'] if report['risk_score'] > 50 else COLORS['WARNING'] if report['risk_score'] > 20 else COLORS['GREEN']}{report['risk_score']}/100{COLORS['ENDC']}\n")

def main():
    parser = argparse.ArgumentParser(description="Phish-Guard: Zero-Dependency Email Header & URL Analyzer")
    parser.add_argument("email_file", help="Path to the raw .eml email file")
    args = parser.parse_args()

    print(f"{COLORS['BLUE']}[*] Parsing email file: {args.email_file}...{COLORS['ENDC']}")
    msg = parse_email(args.email_file)
    report = analyze_headers(msg)
    print_report(report)

if __name__ == "__main__":
    main()