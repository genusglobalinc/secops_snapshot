#!/usr/bin/env python3
"""
Passive Security Exposure Snapshot CLI
Author: You
Purpose:
- Automates passive reconnaissance
- Logs all outputs for reporting
- Generates Markdown + PDF report
- Designed for later full automation

IMPORTANT:
- NO intrusive scanning by default
- Any active steps must require explicit authorization
"""

import os
import json
import subprocess
import datetime
import shutil
from pathlib import Path

import logging

# Logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("secops_snapshot")

# =========================
# CONFIGURATION
# =========================

BASE_DIR = Path.home() / "secops"
CLIENTS_DIR = BASE_DIR / "clients"

REPORT_TEMPLATE = """
# Passive Security Exposure Snapshot

Prepared for: {{business_name}}
Website: {{domain}}
Date: {{date}}
Prepared by: {{prepared_by}}

---

## 1. Executive Summary
Overall Exposure Rating: {{exposure_rating}}
Overall Exposure Score: {{exposure_score}} / 100

{{summary}}

---

## 2. Exposure Overview
{{exposure_table}}

---

## 3. Key Observations
{{key_observations}}

---

## 4. Recommended Next Steps
{{recommendations}}

---

## 5. Authorization & Disclosure
This report was generated using **passive analysis only**.
No authentication attempts, exploitation, or service disruption occurred.

---

## 6. Optional Consultation
Contact: {{contact}}
"""

CHECKLIST_ITEMS = {
    "whois": False,
    "dns": False,
    "ssl": False,
    "headers": False,
    "robots": False,
    "tech_stack": False,
    "subdomains": False,
    "crtsh": False,
    "shodan": False,
    "screenshots": False,
    "risk_score": False,
    "report_generated": False
}

# =========================
# UTILITY FUNCTIONS
# =========================

def run_cmd(cmd, output_file, desc=None, timeout=120):
    """Run shell command and log output to a file"""
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    logger.debug("Executing command%s: %s", f" ({desc})" if desc else "", cmd)
    logger.debug("Output will be written to: %s", output_file)
    missing = _missing_pipeline_tools(cmd)
    if missing:
        logger.warning("Missing tools in pipeline: %s", ", ".join(missing))
    try:
        with open(output_file, "w", encoding="utf-8", errors="ignore") as f:
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
        logger.debug("Command finished with return code %s", result.returncode)
        if result.returncode != 0:
            logger.warning("Command returned non-zero exit code: %s", result.returncode)
    except subprocess.TimeoutExpired:
        logger.exception("Command timed out after %s seconds", timeout)
    except Exception:
        logger.exception("Error while executing command")

def prompt(msg):
    return input(f"[+] {msg}: ").strip()

def yes_no(msg):
    return input(f"[?] {msg} (y/n): ").lower().startswith("y")

def _missing_pipeline_tools(cmd: str):
    tools = []
    for segment in cmd.split("|"):
        segment = segment.strip()
        if not segment:
            continue
        base = segment.split()[0].strip("\"'")
        if base.startswith("http"):
            continue
        # Skip common shell builtins that may not resolve via which
        if base.lower() in {"sort"}:
            continue
        if shutil.which(base) is None:
            tools.append(base)
    return tools

# =========================
# CASE INITIALIZATION
# CHECKLIST: (none)
#BMGD5KD6XEBYR8HDP7Z9HQUM
# =========================

def init_case():
    logger.debug("init_case(): starting")
    client = prompt("Client short name (e.g. acme_corp)")
    domain = prompt("Primary domain (example.com)")
    business = prompt("Business legal name")

    case_dir = CLIENTS_DIR / client
    dirs = ["scope", "recon", "scans", "evidence", "reports", "notes"]

    for d in dirs:
        (case_dir / d).mkdir(parents=True, exist_ok=True)

    logger.debug("init_case(): created case directories at %s", case_dir)
    scope_file = case_dir / "scope" / "scope.txt"
    scope_file.write_text(
        f"Domain: {domain}\n"
        "Scope: Passive analysis only\n"
        "No authentication, exploitation, or active scanning\n"
    )

    state = {
        "client": client,
        "business_name": business,
        "domain": domain,
        "date": str(datetime.date.today()),
        "checklist": CHECKLIST_ITEMS.copy(),
        "findings": [],
        "risk_score": 0
    }

    with open(case_dir / "notes" / "state.json", "w") as f:
        json.dump(state, f, indent=2)
    logger.debug("init_case(): state written to %s", case_dir / "notes" / "state.json")
    logger.debug("init_case(): initialized (client=%s, domain=%s, date=%s)", client, domain, state["date"])
    print("[+] Case initialized")
    return case_dir, state

# =========================
# RECON PHASE
# =========================

def whois_lookup(case_dir, state):
    logger.debug("Starting whois_lookup for domain %s", state["domain"])
    # CHECKLIST: whois
    out = case_dir / "recon" / "whois.txt"
    logger.debug("whois_lookup(): writing to %s", out)
    run_cmd(f"whois {state['domain']}", out, desc="whois")
    state["checklist"]["whois"] = True
    logger.debug("whois_lookup(): complete")

def dns_lookup(case_dir, state):
    logger.debug("Starting dns_lookup for domain %s", state["domain"])
    # CHECKLIST: dns
    out = case_dir / "recon" / "dns.txt"
    logger.debug("dns_lookup(): writing to %s", out)
    run_cmd(f"dig {state['domain']} ANY +noall +answer", out, desc="dig")
    state["checklist"]["dns"] = True
    logger.debug("dns_lookup(): complete")

def headers_check(case_dir, state):
    logger.debug("Starting headers_check for domain %s", state["domain"])
    # CHECKLIST: headers
    out = case_dir / "recon" / "headers.txt"
    logger.debug("headers_check(): writing to %s", out)
    run_cmd(f"curl -I https://{state['domain']}", out, desc="headers_check")
    state["checklist"]["headers"] = True
    logger.debug("headers_check(): complete")

def robots_check(case_dir, state):
    logger.debug("Starting robots_check for domain %s", state["domain"])
    # CHECKLIST: robots
    out = case_dir / "recon" / "robots.txt"
    logger.debug("robots_check(): writing to %s", out)
    run_cmd(f"curl https://{state['domain']}/robots.txt", out, desc="robots_check")
    state["checklist"]["robots"] = True
    logger.debug("robots_check(): complete")

def whatweb_scan(case_dir, state):
    logger.debug("Starting whatweb_scan for domain %s", state["domain"])
    # CHECKLIST: tech_stack
    out = case_dir / "recon" / "whatweb.txt"
    logger.debug("whatweb_scan(): writing to %s", out)
    run_cmd(f"whatweb -a 3 https://{state['domain']}", out, desc="whatweb")
    state["checklist"]["tech_stack"] = True
    logger.debug("whatweb_scan(): complete")

def subdomain_enum(case_dir, state):
    logger.debug("Starting subdomain_enum for domain %s", state["domain"])
    # CHECKLIST: subdomains
    out = case_dir / "recon" / "subdomains.txt"
    logger.debug("subdomain_enum(): writing to %s", out)
    run_cmd(f"subfinder -d {state['domain']} -silent", out, desc="subfinder")
    state["checklist"]["subdomains"] = True
    logger.debug("subdomain_enum(): complete")

def crtsh_lookup(case_dir, state):
    logger.debug("Starting crtsh_lookup for domain %s", state["domain"])
    # CHECKLIST: crtsh
    out = case_dir / "recon" / "crtsh.txt"
    domain = state["domain"]
    if shutil.which("jq") is None:
        logger.warning("jq not found; saving raw crt.sh JSON without filtering")
        cmd = f"curl \"https://crt.sh/?q=%25.{domain}&output=json\""
    else:
        if os.name == "nt":
            cmd = f"curl \"https://crt.sh/?q=%25.{domain}&output=json\" | jq -r \".[].name_value\""
        else:
            cmd = f"curl \"https://crt.sh/?q=%25.{domain}&output=json\" | jq -r \".[].name_value\" | sort -u"
    logger.debug("crtsh_lookup(): writing to %s", out)
    run_cmd(cmd, out, desc="crtsh")
    state["checklist"]["crtsh"] = True
    logger.debug("crtsh_lookup(): complete")

# =========================
# MANUAL INPUT PHASE
# =========================

def manual_ssl(case_dir, state):
    logger.debug("Starting manual_ssl step")
    # CHECKLIST: ssl
    print("[!] Manual Step: Run SSL Labs scan")
    print("    https://www.ssllabs.com/ssltest/")
    notes = prompt("Paste SSL grade & notes")
    (case_dir / "recon" / "ssl_labs.txt").write_text(notes)
    state["checklist"]["ssl"] = True
    logger.debug("manual_ssl(): notes saved to %s", case_dir / "recon" / "ssl_labs.txt")

def manual_shodan(case_dir, state):
    logger.debug("Starting manual_shodan step")
    # CHECKLIST: shodan
    print("[!] Manual Step: Shodan search hostname")
    notes = prompt("Paste Shodan findings")
    (case_dir / "recon" / "shodan.txt").write_text(notes)
    state["checklist"]["shodan"] = True
    logger.debug("manual_shodan(): notes saved to %s", case_dir / "recon" / "shodan.txt")

def upload_screenshots(case_dir, state):
    logger.debug("Starting upload_screenshots step")
    # CHECKLIST: screenshots
    if yes_no("Do you have screenshots to upload?"):
        path = prompt("Path to screenshot directory")
        count = 0
        for file in Path(path).glob("*"):
            shutil.copy(file, case_dir / "evidence")
            count += 1
        state["checklist"]["screenshots"] = True
        logger.debug("upload_screenshots(): copied %d files from %s", count, path)
    else:
        logger.debug("upload_screenshots(): user indicated no screenshots to upload")

# =========================
# RISK SCORING
# =========================

def risk_scoring(case_dir, state):
    logger.debug("Starting risk_scoring step")
    # CHECKLIST: risk_score
    score = int(prompt("Enter overall exposure score (0–100)"))
    state["risk_score"] = score
    state["checklist"]["risk_score"] = True
    logger.debug("risk_scoring(): set risk_score=%s", score)

# =========================
# REPORT GENERATION
# =========================

def generate_report(case_dir, state):
    logger.debug("Starting generate_report step")
    # CHECKLIST: report_generated
    md_path = case_dir / "reports" / "report.md"

    report = REPORT_TEMPLATE
    replacements = {
        "{{business_name}}": state["business_name"],
        "{{domain}}": state["domain"],
        "{{date}}": state["date"],
        "{{prepared_by}}": "Your Business Name",
        "{{exposure_rating}}": "Moderate",
        "{{exposure_score}}": str(state["risk_score"]),
        "{{summary}}": "Passive exposure indicators were identified.",
        "{{exposure_table}}": "Refer to recon outputs.",
        "{{key_observations}}": "See findings.",
        "{{recommendations}}": "Authorized active assessment recommended.",
        "{{contact}}": "you@company.com"
    }

    for k, v in replacements.items():
        report = report.replace(k, v)

    md_path.write_text(report)
    logger.debug("generate_report(): wrote markdown to %s", md_path)

    pdf_path = case_dir / 'reports' / 'report.pdf'
    if shutil.which("pandoc") is None:
        logger.warning("pandoc not found; skipping PDF generation")
    else:
        logger.debug("generate_report(): invoking pandoc to produce %s", pdf_path)
        result = subprocess.run(
            f"pandoc \"{md_path}\" -o \"{pdf_path}\"",
            shell=True
        )
        logger.debug("pandoc return code: %s", getattr(result, "returncode", None))

    state["checklist"]["report_generated"] = True

# =========================
# MAIN
# =========================

def main():
    logger.debug("Entering main()")
    case_dir, state = init_case()

    # === Automated Passive Recon ===
    # Step: WHOIS lookup
    logger.debug("main(): whois_lookup() start")
    whois_lookup(case_dir, state)
    logger.debug("main(): whois_lookup() complete")
    # Step: DNS lookup
    logger.debug("main(): dns_lookup() start")
    dns_lookup(case_dir, state)
    logger.debug("main(): dns_lookup() complete")
    # Step: HTTP security headers check
    logger.debug("main(): headers_check() start")
    headers_check(case_dir, state)
    logger.debug("main(): headers_check() complete")
    # Step: robots.txt retrieval
    logger.debug("main(): robots_check() start")
    robots_check(case_dir, state)
    logger.debug("main(): robots_check() complete")
    # Step: WhatWeb technology fingerprint
    logger.debug("main(): whatweb_scan() start")
    whatweb_scan(case_dir, state)
    logger.debug("main(): whatweb_scan() complete")
    # Step: Subdomain enumeration
    logger.debug("main(): subdomain_enum() start")
    subdomain_enum(case_dir, state)
    logger.debug("main(): subdomain_enum() complete")
    # Step: crt.sh certificate transparency search
    logger.debug("main(): crtsh_lookup() start")
    crtsh_lookup(case_dir, state)
    logger.debug("main(): crtsh_lookup() complete")

    # === Manual Intelligence ===
    # Step: SSL Labs
    logger.debug("main(): manual_ssl() start")
    manual_ssl(case_dir, state)
    logger.debug("main(): manual_ssl() complete")
    # Step: Shodan
    logger.debug("main(): manual_shodan() start")
    manual_shodan(case_dir, state)
    logger.debug("main(): manual_shodan() complete")
    # Step: Upload screenshots
    logger.debug("main(): upload_screenshots() start")
    upload_screenshots(case_dir, state)
    logger.debug("main(): upload_screenshots() complete")

    # === Risk & Report ===
    logger.debug("main(): risk_scoring() start")
    risk_scoring(case_dir, state)
    logger.debug("main(): risk_scoring() complete")
    logger.debug("main(): generate_report() start")
    generate_report(case_dir, state)
    logger.debug("main(): generate_report() complete")

    # Save final state
    with open(case_dir / "notes" / "state.json", "w") as f:
        json.dump(state, f, indent=2)

    print("[+] Assessment complete")

if __name__ == "__main__":
    try:
        logger.debug("Launching secops_snapshot main()")
        main()
        logger.debug("secops_snapshot completed successfully")
    except Exception:
        logger.exception("Unhandled exception during execution")
        raise
