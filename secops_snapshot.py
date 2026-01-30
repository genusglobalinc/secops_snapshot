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
import re
from urllib.parse import urlparse, quote_plus
import urllib.request
import urllib.error
import getpass
import socket
import ssl
import io
import sys
import argparse
import smtplib
from email.message import EmailMessage
from email.utils import formatdate
import mimetypes
import time
try:
    from openai import OpenAI as _OpenAIClient  # New-style client
except Exception:  # pragma: no cover
    _OpenAIClient = None
try:
    import openai as _openai_mod  # Legacy client
except Exception:  # pragma: no cover
    _openai_mod = None

# Google APIs (optional)
try:
    from googleapiclient.discovery import build as _gbuild
    from googleapiclient.http import MediaFileUpload as _MediaFileUpload
    from googleapiclient.http import MediaIoBaseUpload as _MediaIoBaseUpload
    from google_auth_oauthlib.flow import InstalledAppFlow as _InstalledAppFlow
    from google.oauth2.credentials import Credentials as _GoogleCredentials
    from google.auth.transport.requests import Request as _GoogleRequest
except Exception:  # pragma: no cover
    _gbuild = None
    _MediaFileUpload = None
    _MediaIoBaseUpload = None
    _InstalledAppFlow = None
    _GoogleCredentials = None
    _GoogleRequest = None

import logging

# Logging configuration (INFO by default; DEBUG when SECOPS_DEBUG=1)
_env_level = os.getenv("SECOPS_LOG_LEVEL") or ("DEBUG" if os.getenv("SECOPS_DEBUG") else "INFO")
_log_level = getattr(logging, str(_env_level).upper(), logging.INFO)
logging.basicConfig(
    level=_log_level,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("secops_snapshot")

class _InMemoryLogHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records = []
    def emit(self, record):
        try:
            msg = self.format(record)
        except Exception:
            msg = record.getMessage()
        self.records.append(msg)

_log_memory_handler = _InMemoryLogHandler()
_log_memory_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s - %(message)s"))
logger.addHandler(_log_memory_handler)

# Quiet noisy third-party debug logs unless explicitly in DEBUG
if _log_level > logging.DEBUG:
    for _name in [
        "httpx", "httpcore", "urllib3",
        "googleapiclient", "googleapiclient.discovery", "googleapiclient.http",
        "openai",
    ]:
        try:
            logging.getLogger(_name).setLevel(logging.WARNING)
        except Exception:
            pass

# =========================
# CONFIGURATION
# =========================

BASE_DIR = Path.home() / "secops"
CLIENTS_DIR = BASE_DIR / "clients"
CONFIG_FILE = BASE_DIR / "config.json"
OUTREACH_LOG_FILE = BASE_DIR / "outreach.json"

# Google integration settings
GOOGLE_SCOPES = [
    'https://www.googleapis.com/auth/drive.file',
    'https://www.googleapis.com/auth/documents',
    'https://www.googleapis.com/auth/spreadsheets',
]
GOOGLE_TOKEN_FILE = BASE_DIR / "google_token.json"

REPORT_TEMPLATE = """
# Passive Security Exposure Snapshot

Prepared for: {{Business Name}}
Website: {{domain}}
Date: {{date}}
Prepared by: {{Your Business Name}}

---

## 1. Executive Summary
This snapshot provides a high‑level overview of publicly observable security exposures associated with your
website and online presence. The findings below are based only on passive analysis and publicly
available information — no intrusive testing or exploitation was performed.

Overall Exposure Rating: {{Overall Exposure Rating}}
Overall Exposure Score: {{Overall Exposure Score}}

In its current state, your digital presence exposes information that could increase the likelihood of:
- Unauthorized access attempts
- Service disruption or downtime
- Credential abuse or account takeover
- Reputational and financial impact

This report is intended to help you understand risk, not to alarm — and to outline clear next steps if you
choose to reduce exposure.

---

## 2. Exposure Overview

| Area | Status | Risk Level |
|---|---|---|
| Domain & DNS Configuration | Observed | {{Area_Domain_DNS}} |
| Website Technology Stack | Observed | {{Area_Tech_Stack}} |
| Email & Credential Exposure | Observed | {{Area_Email_Creds}} |
| SSL / Transport Security | Observed | {{Area_SSL}} |
| Security Headers | Observed | {{Area_Sec_Headers}} |

---

## 3. Key Observations (Top 3–5)
{{observations_section}}

---

## 4. Exposure Risk Score
Overall Exposure Score: {{Overall Exposure Score}}
This score reflects how easily a threat actor could gather information about your systems using the same
techniques commonly employed in real‑world attacks against small businesses.
Note: This score does not represent confirmed exploitation — only exposure likelihood.

---

## 5. Recommended Next Steps
To better understand and reduce risk, organizations typically proceed with:
- Authorized active vulnerability scanning
- Manual validation of findings
- Prioritized remediation guidance
- Optional retesting after fixes

These steps require explicit written authorization and are not included in this snapshot.

---

## 6. Authorization & Disclosure
This report was generated using passive analysis methods only:
- No login attempts were made
- No exploitation was performed
- No service disruption occurred

All findings are based on publicly accessible information at the time of review.

---

## 7. Optional Consultation
If you would like:
- Clarification on any findings
- A deeper authorized assessment
- Assistance reducing exposure

You may request a 30‑minute consultation to review this snapshot and discuss next steps.
Contact: {{contact}}

This report is confidential and intended solely for the recipient listed above.
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

def prompt_multiline(msg: str, end_marker: str = "END") -> str:
    print(f"[+] {msg} (finish with a single line '{end_marker}')")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == end_marker:
            break
        lines.append(line)
    return "\n".join(lines).strip()

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

def _normalize_domain(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return s
    u = urlparse(s if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', s) else f"//{s}", allow_fragments=False)
    host = u.netloc or u.path
    host = host.split('/')[0]
    if ':' in host:
        host = host.split(':')[0]
    host = host.strip().strip('.')
    return host

def _safe_slug(s: str) -> str:
    s = (s or "").strip().replace(" ", "_")
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", s)
    s = s.strip("-_.")
    return s or "client"

def _extract_score(text: str, lo: int, hi: int):
    if text is None:
        return None
    for part in str(text).splitlines():
        m = re.fullmatch(r"\s*(\d{1,3})\s*", part)
        if m:
            v = int(m.group(1))
            if lo <= v <= hi:
                return v
    return None

def _prompt_int_in_range(msg: str, lo: int = 0, hi: int = 100) -> int:
    while True:
        raw = prompt(msg)
        val = _extract_score(raw, lo, hi)
        if val is not None:
            return val
        logger.warning("Please enter an integer between %s and %s.", lo, hi)

def _read_text(path: Path, default: str = "") -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return default

def _sanitize_ascii(text: str) -> str:
    if not text:
        return text
    repl = {
        "–": "-", "—": "-", "‑": "-", "−": "-",
        "•": "-", "·": "-",
        "“": '"', "”": '"', "„": '"',
        "’": "'", "‘": "'", "´": "'",
        "…": "...",
        "✓": "[x]", "✔": "[x]", "✗": "[ ]",
        "→": "->", "←": "<-",
        "\u00A0": " ", "\u200B": "",
    }
    for k, v in repl.items():
        text = text.replace(k, v)
    out = []
    for ch in text:
        o = ord(ch)
        if o in (9, 10, 13) or (32 <= o <= 126):
            out.append(ch)
        else:
            # drop non-ascii control/unicode
            pass
    return "".join(out)

def _summarize_shodan_text(text: str, max_ips: int = 10, max_ports: int = 10, max_cves: int = 10) -> str:
    if not text:
        return "(no Shodan data)"
    import re as _re
    ips = []
    ports = {}
    cves = set()
    services = {k: 0 for k in [
        "http", "https", "ssl", "ssh", "rdp", "ftp", "smtp", "imap", "pop3",
        "mysql", "postgres", "mongodb", "redis", "elasticsearch", "memcached"
    ]}
    waf = {"cloudflare": 0}
    for ln in text.splitlines():
        l = ln.strip()
        if not l:
            continue
        ll = l.lower()
        # IPs
        for ip in _re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", l):
            if ip not in ips:
                ips.append(ip)
        # Ports via 'port: N' or ':N' after IP
        for p in _re.findall(r"\bport[:=]\s*(\d{1,5})\b", ll):
            ports[p] = ports.get(p, 0) + 1
        for m in _re.finditer(r"\b(?:\d{1,3}\.){3}\d{1,3}[: ](\d{1,5})\b", l):
            p = m.group(1)
            ports[p] = ports.get(p, 0) + 1
        # CVEs
        for c in _re.findall(r"\bCVE-\d{4}-\d{3,7}\b", l, _re.I):
            cves.add(c.upper())
        # Services
        for s in services.keys():
            if s in ll:
                services[s] += 1
        # WAF/provider hints
        if "cloudflare" in ll:
            waf["cloudflare"] += 1
    # Compose summary
    lines = []
    if ips:
        lines.append(f"Unique IPs observed: {len(ips)}")
        lines.append("Sample IPs: " + ", ".join(ips[:max_ips]))
    if ports:
        top_ports = sorted(ports.items(), key=lambda kv: (-kv[1], int(kv[0]) if kv[0].isdigit() else 0))[:max_ports]
        lines.append("Top open ports: " + ", ".join([f"{p} (n={c})" for p, c in top_ports]))
    notable_services = [f"{k} (n={v})" for k, v in services.items() if v]
    if notable_services:
        lines.append("Notable services: " + ", ".join(notable_services))
    if cves:
        top_cves = sorted(cves)[:max_cves]
        lines.append("CVEs mentioned: " + ", ".join(top_cves))
    if waf.get("cloudflare"):
        lines.append("Provider/WAF indicators: Cloudflare")
    if not lines:
        return "(no salient Shodan signals found)"
    return "\n".join(lines)

def _load_config() -> dict:
    try:
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        pass
    return {}

def _prompt_secret(message: str) -> str:
    """Prompt for a secret. Uses getpass by default. Fallbacks:
    - If SECOPS_VISIBLE_INPUT=1, use visible input() warning that input will be echoed.
    - If user enters a value starting with '@', treat the remainder as a file path and read the first line.
    """
    try:
        if os.getenv("SECOPS_VISIBLE_INPUT"):
            print("[!] Input will be visible on screen.")
            val = input(f"{message} ")
        else:
            val = getpass.getpass(f"{message} ")
    except Exception:
        # Fallback to visible input in non-TTY environments
        print("[!] Secure input not available; input will be visible.")
        val = input(f"{message} ")
    val = (val or "").strip()
    if val.startswith("@") and len(val) > 1:
        path = val[1:].strip().strip('"')
        try:
            txt = Path(path).read_text(encoding="utf-8", errors="ignore").strip()
            # take the first non-empty line
            for line in txt.splitlines():
                line = line.strip()
                if line and not line.lower().startswith("open ai key"):
                    return line
            return txt
        except Exception:
            logger.exception("Failed to read secret from file: %s", path)
    return val

def _get_prepared_by(interactive: bool = True) -> str:
    cfg = _load_config()
    val = (cfg.get("prepared_by") or "").strip()
    if val:
        return val
    if not interactive:
        return "Your Business Name"
    try:
        v = prompt("Prepared by (your org/brand name)")
        v = (v or "Your Business Name").strip()
        cfg["prepared_by"] = v
        _save_config(cfg)
        return v
    except Exception:
        return "Your Business Name"

def _get_contact_for(domain: str) -> str:
    cfg = _load_config()
    contacts = cfg.get("contacts") or {}
    return (contacts.get(_normalize_domain(domain)) or "").strip()

def _remember_contact(domain: str, email: str) -> None:
    if not domain or not email:
        return
    try:
        cfg = _load_config()
        contacts = cfg.get("contacts") or {}
        contacts[_normalize_domain(domain)] = email.strip()
        cfg["contacts"] = contacts
        _save_config(cfg)
    except Exception:
        logger.exception("Failed to persist contact mapping for %s", domain)

def _get_default_contact(interactive: bool = True) -> str:
    cfg = _load_config()
    val = (cfg.get("default_contact") or "").strip()
    if val:
        return val
    if not interactive:
        return "you@company.com"
    try:
        v = prompt("Default contact email (used in reports)")
        v = (v or "you@company.com").strip()
        cfg["default_contact"] = v
        _save_config(cfg)
        return v
    except Exception:
        return "you@company.com"

def _save_config(cfg: dict) -> None:
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = json.dumps(cfg or {}, indent=2)
        CONFIG_FILE.write_text(tmp, encoding="utf-8")
    except Exception:
        logger.exception("Failed to save config at %s", CONFIG_FILE)

def _load_outreach_log() -> dict:
    try:
        if OUTREACH_LOG_FILE.exists():
            return json.loads(OUTREACH_LOG_FILE.read_text(encoding="utf-8", errors="ignore")) or {}
    except Exception:
        pass
    return {"entries": []}

def _save_outreach_log(data: dict) -> None:
    try:
        OUTREACH_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        OUTREACH_LOG_FILE.write_text(json.dumps(data or {"entries": []}, indent=2), encoding="utf-8")
    except Exception:
        logger.exception("Failed to save outreach log at %s", OUTREACH_LOG_FILE)

def _get_or_create_outreach_entry(domain: str, email: str, init: dict = None) -> dict:
    log = _load_outreach_log()
    entries = log.get("entries") or []
    key_dom = _normalize_domain(domain)
    key_email = (email or "").strip().lower()
    for e in entries:
        if (e.get("domain") == key_dom) and (e.get("email") == key_email):
            return e
    entry = {"domain": key_dom, "email": key_email}
    if init:
        entry.update(init)
    entries.append(entry)
    log["entries"] = entries
    _save_outreach_log(log)
    return entry

def _update_outreach_entry(entry: dict, updates: dict) -> None:
    log = _load_outreach_log()
    entries = log.get("entries") or []
    for i, e in enumerate(entries):
        if (e.get("domain") == entry.get("domain")) and (e.get("email") == entry.get("email")):
            e.update(updates or {})
            entries[i] = e
            break
    log["entries"] = entries
    _save_outreach_log(log)

EMAIL_TEMPLATE_INITIAL_SUBJ = "Passive security snapshot for {{Company Name}}"
EMAIL_TEMPLATE_INITIAL_BODY = (
    "Hi {{TeamOrName}},\n\n"
    "I’m Jyasi Davis, reaching out because I recently completed a passive security exposure snapshot of {{Company Name}}’s public web presence.\n\n"
    "This review used only publicly available information, no scanning, no login attempts, and no intrusive testing of any kind. The intent was simply to identify areas where publicly visible configuration details could increase risk over time.\n\n"
    "I’ve attached a short PDF report for your reference.\n\n"
    "It highlights a few items that are common for growing teams and are typically straightforward to address once identified.\n\n"
    "If it’s helpful, I’m happy to:\n"
    "- Walk through the findings briefly (10–15 minutes),\n"
    "- Answer any questions after you’ve reviewed the report, or\n"
    "- Leave it with you purely as informational reference, no obligation.\n\n"
    "If you’d like a quick walkthrough, feel free to reply here or call/text me at 850-329-8951.\n\n"
    "Best regards,\n"
    "Jyasi Davis\n"
    "Genus Studios\n"
    "https://www.linkedin.com/in/jyasi-davis-7082241b4/\n"
    "gstudiosdevops@gmail.com\n"
    "850-329-8951\n"
)

EMAIL_TEMPLATE_FU1_SUBJ = "Following up on the passive security snapshot for {{Company Name}}"
EMAIL_TEMPLATE_FU1_BODY = (
    "Hi {{TeamOrName}},\n\n"
    "I wanted to follow up on the passive security snapshot I shared a couple of days ago regarding {{Company Name}}’s public web presence.\n\n"
    "The attached report highlights a few areas that are common for growing teams and are usually easy to address once identified.\n\n"
    "If helpful, I can:\n"
    "- Walk you through the findings briefly (10–15 minutes),\n"
    "- Answer any questions after you’ve reviewed it, or\n"
    "- Leave it with you purely as informational reference — no obligation.\n\n"
    "I’m happy to coordinate a time that works for you. You can reply here or reach me directly at 850-329-8951.\n\n"
    "Best regards,\n"
    "Jyasi Davis\n"
    "Genus Studios\n"
    "https://www.linkedin.com/in/jyasi-davis-7082241b4/\n"
    "gstudiosdevops@gmail.com\n"
    "850-329-8951\n"
)

EMAIL_TEMPLATE_FU2_SUBJ = "Quick check-in on {{Company Name}}’s security snapshot"
EMAIL_TEMPLATE_FU2_BODY = (
    "Hi {{TeamOrName}},\n\n"
    "I wanted to make one last check-in regarding the passive security snapshot I shared for {{Company Name}}’s public web presence.\n\n"
    "Many small teams find these reports useful for quickly identifying low-effort, high-impact improvements to reduce security risk — even if it’s just to have the findings documented for future reference.\n\n"
    "If it’s of interest, I’m happy to:\n"
    "- Walk through the findings briefly (10–15 minutes),\n"
    "- Answer any questions after review, or\n"
    "- Simply leave the report for your records.\n\n"
    "If now isn’t the right time, no worries at all — I’m happy to reconnect whenever it’s convenient for you. You can reply here or reach me at 850-329-8951.\n\n"
    "Best regards,\n"
    "Jyasi Davis\n"
    "Genus Studios\n"
    "https://www.linkedin.com/in/jyasi-davis-7082241b4/\n"
    "gstudiosdevops@gmail.com\n"
    "850-329-8951\n"
)

def _render_email(kind: str, company: str, team_or_name: str):
    company = (company or "").strip() or "your team"
    team = (team_or_name or "Team").strip()
    if kind == "fu1":
        subj = EMAIL_TEMPLATE_FU1_SUBJ.replace("{{Company Name}}", company)
        body = EMAIL_TEMPLATE_FU1_BODY.replace("{{Company Name}}", company).replace("{{TeamOrName}}", team)
    elif kind == "fu2":
        subj = EMAIL_TEMPLATE_FU2_SUBJ.replace("{{Company Name}}", company)
        body = EMAIL_TEMPLATE_FU2_BODY.replace("{{Company Name}}", company).replace("{{TeamOrName}}", team)
    else:
        subj = EMAIL_TEMPLATE_INITIAL_SUBJ.replace("{{Company Name}}", company)
        body = EMAIL_TEMPLATE_INITIAL_BODY.replace("{{Company Name}}", company).replace("{{TeamOrName}}", team)
    return _sanitize_ascii(subj), _sanitize_ascii(body)

def setup_email_interactive(force_all: bool = False):
    cfg = _load_config()
    ec = cfg.get("email_smtp") or {}
    if force_all:
        cur_host = ec.get("host") or "smtp.gmail.com"
        host_in = prompt(f"SMTP server (default {cur_host})")
        host = host_in or cur_host
        try:
            cur_port = str(ec.get("port") or "587")
            port_in = prompt(f"SMTP port (587 for STARTTLS, 465 for SSL) (default {cur_port})")
            port = int(port_in or cur_port)
        except Exception:
            port = int(ec.get("port") or 587)
        cur_user = ec.get("username") or ""
        user_in = prompt(f"SMTP username (usually your email) (default {cur_user})")
        user = user_in or cur_user
        cur_from_email = ec.get("from_email") or user
        from_email_in = prompt(f"From email (address shown to recipients) (default {cur_from_email})")
        from_email = from_email_in or cur_from_email
        try:
            prepared_by = _get_prepared_by(interactive=False)
        except Exception:
            prepared_by = ""
        cur_from_name = ec.get("from_name") or (prepared_by or "")
        from_name_in = prompt(f"From name (display name) (default {cur_from_name})")
        from_name = from_name_in or cur_from_name
        # Infer TLS/SSL from port selection when forcing re-entry
        if int(port) == 465:
            use_ssl = True
            use_tls = False
        else:
            use_ssl = False
            use_tls = True
        if yes_no("Save SMTP password to config for reuse?"):
            pw = _prompt_secret("Enter SMTP password (or app password):")
        else:
            pw = ec.get("password", "")
    else:
        host = (ec.get("host") or prompt("SMTP server (e.g., smtp.gmail.com)")) or "smtp.gmail.com"
        try:
            port = int((ec.get("port") or prompt("SMTP port (587 for STARTTLS, 465 for SSL)")) or "587")
        except Exception:
            port = 587
        use_ssl = bool(ec.get("use_ssl"))
        use_tls = bool(ec.get("use_tls", True))
        if not use_ssl and not use_tls:
            use_tls = True
        user = (ec.get("username") or prompt("SMTP username (usually your email)"))
        from_email = (ec.get("from_email") or prompt("From email (address shown to recipients)")) or user
        try:
            prepared_by = _get_prepared_by(interactive=False)
        except Exception:
            prepared_by = ""
        from_name = (ec.get("from_name") or prompt("From name (display name)")) or (prepared_by or "")
        if yes_no("Save SMTP password to config for reuse?"):
            pw = _prompt_secret("Enter SMTP password (or app password):")
        else:
            pw = ec.get("password", "")
    new_cfg = {
        "host": host,
        "port": int(port),
        "use_ssl": bool(use_ssl),
        "use_tls": bool(use_tls),
        "username": user,
        "from_email": from_email,
        "from_name": from_name,
    }
    if pw:
        new_cfg["password"] = pw
    cfg["email_smtp"] = new_cfg
    _save_config(cfg)

def _get_email_config(interactive: bool = True) -> dict:
    cfg = _load_config()
    ec = cfg.get("email_smtp") or {}
    needed = ["host", "port", "username", "from_email"]
    ok = all(str(ec.get(k) or "").strip() for k in needed)
    if ok:
        return ec
    if interactive:
        setup_email_interactive()
        cfg = _load_config()
        return cfg.get("email_smtp") or {}
    return {}

def _send_email(smtp_cfg: dict, to_email: str, subject: str, body: str, attachments: list = None) -> bool:
    to_email = (to_email or "").strip()
    if not to_email:
        print("[!] No recipient email provided; skipping send")
        return False
    host = smtp_cfg.get("host")
    port = int(smtp_cfg.get("port") or 587)
    use_ssl = bool(smtp_cfg.get("use_ssl"))
    use_tls = bool(smtp_cfg.get("use_tls", True))
    user = smtp_cfg.get("username")
    pw = smtp_cfg.get("password") or _prompt_secret("SMTP password:")
    from_email = smtp_cfg.get("from_email") or user
    from_name = smtp_cfg.get("from_name") or from_email
    msg = EmailMessage()
    if from_name and from_name != from_email:
        msg["From"] = f"{from_name} <{from_email}>"
    else:
        msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg.set_content(body)
    for ap in (attachments or []):
        try:
            path = Path(ap)
            if not path.exists():
                continue
            ctype, _enc = mimetypes.guess_type(str(path))
            if ctype is None:
                ctype = "application/octet-stream"
            maintype, subtype = ctype.split("/", 1)
            with open(path, "rb") as f:
                data = f.read()
            msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=path.name)
        except Exception:
            logger.exception("Failed attaching %s", ap)
    attempts = 0
    while attempts < 2:
        attempts += 1
        try:
            server = smtplib.SMTP_SSL(host, port) if use_ssl else smtplib.SMTP(host, port)
            try:
                if os.getenv("SECOPS_SMTP_DEBUG"):
                    try:
                        server.set_debuglevel(1)
                    except Exception:
                        pass
                server.ehlo()
                if (not use_ssl) and use_tls:
                    server.starttls()
                    try:
                        server.ehlo()
                    except Exception:
                        pass
                if user:
                    server.login(user, pw)
                server.send_message(msg)
                print(f"[+] Email sent to {to_email}")
                return True
            finally:
                try:
                    server.quit()
                except Exception:
                    pass
        except smtplib.SMTPAuthenticationError as e:
            logger.error("SMTP auth failed (%s): %s", getattr(e, 'smtp_code', 'auth'), getattr(e, 'smtp_error', e))
            print("[!] SMTP authentication failed. Check username/App Password and server settings.")
            return False
        except smtplib.SMTPServerDisconnected as e:
            logger.warning("SMTP server disconnected: %s", e)
            print("[!] SMTP server disconnected; retrying once...")
            time.sleep(2)
            continue
        except smtplib.SMTPConnectError as e:
            logger.error("SMTP connect error (%s): %s", getattr(e, 'smtp_code', 'connect'), getattr(e, 'smtp_error', e))
            print("[!] Could not connect to SMTP server. Verify host/port and network access.")
            return False
        except smtplib.SMTPRecipientsRefused as e:
            logger.error("SMTP recipients refused: %s", e)
            print("[!] Recipient address refused by server.")
            return False
        except smtplib.SMTPSenderRefused as e:
            logger.error("SMTP sender refused: %s", e)
            print("[!] Sender address refused by server. Check from_email/username match.")
            return False
        except smtplib.SMTPResponseException as e:
            logger.error("SMTP response error (%s): %s", getattr(e, 'smtp_code', '?'), getattr(e, 'smtp_error', e))
            print("[!] SMTP server returned an error response.")
            return False
        except Exception as e:
            logger.exception("Email send failed to %s", to_email)
            print(f"[!] Email send error: {e}")
            return False
    print("[!] Email send failed after retry")
    return False

def send_outreach_post_report(case_dir, state, to_email: str, recipient_name: str = None, interactive: bool = True) -> bool:
    company = state.get("business_name") or state.get("domain")
    subject, body = _render_email("initial", company, recipient_name or "Team")
    pdf_path = case_dir / "reports" / "report.pdf"
    if pdf_path.exists():
        atts = [str(pdf_path)]
    else:
        atts = [str(case_dir / "reports" / "report.md")]
    smtp_cfg = _get_email_config(interactive=True)
    ok = _send_email(smtp_cfg, to_email, subject, body, atts)
    if (not ok) and interactive:
        try:
            if yes_no("Email failed. Re-enter SMTP settings and retry now?"):
                setup_email_interactive(force_all=True)
                smtp_cfg = _get_email_config(interactive=True)
                ok = _send_email(smtp_cfg, to_email, subject, body, atts)
        except Exception:
            logger.exception("Interactive SMTP retry failed")
    if ok:
        now = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        entry = _get_or_create_outreach_entry(state.get("domain"), to_email, init={
            "client": state.get("client"),
            "business_name": state.get("business_name"),
            "report_path": atts[0],
        })
        _update_outreach_entry(entry, {"initial_sent_at": now})
    return ok

def _parse_iso(ts: str):
    try:
        return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None

def process_due_followups() -> int:
    smtp_cfg = _get_email_config(interactive=True)
    log = _load_outreach_log()
    entries = log.get("entries") or []
    now = datetime.datetime.utcnow()
    sent = 0
    for e in entries:
        dom = e.get("domain")
        em = e.get("email")
        company = e.get("business_name") or dom
        report_path = e.get("report_path")
        initial_ts = _parse_iso(e.get("initial_sent_at"))
        fu1_ts = _parse_iso(e.get("followup1_sent_at"))
        fu2_ts = _parse_iso(e.get("followup2_sent_at"))
        try:
            if initial_ts and (not fu1_ts):
                if (now - initial_ts) >= datetime.timedelta(hours=48):
                    subj, body = _render_email("fu1", company, "Team")
                    ok = _send_email(smtp_cfg, em, subj, body, [p for p in [report_path] if p and Path(p).exists()])
                    if ok:
                        _update_outreach_entry(e, {"followup1_sent_at": now.replace(microsecond=0).isoformat() + "Z"})
                        sent += 1
                        continue
            if fu1_ts and (not fu2_ts):
                if (now - fu1_ts) >= datetime.timedelta(hours=72):
                    subj, body = _render_email("fu2", company, "Team")
                    ok = _send_email(smtp_cfg, em, subj, body, [p for p in [report_path] if p and Path(p).exists()])
                    if ok:
                        _update_outreach_entry(e, {"followup2_sent_at": now.replace(microsecond=0).isoformat() + "Z"})
                        sent += 1
                        continue
        except Exception:
            logger.exception("Follow-up processing failed for %s", em)
    return sent

def _get_openai_api_key(interactive: bool = True) -> str:
    env_key = os.getenv("OPENAI_API_KEY")
    if env_key:
        return env_key.strip()
    cfg = _load_config()
    if cfg.get("openai_api_key"):
        return str(cfg["openai_api_key"]).strip()
    if not interactive:
        return ""
    print("[!] OpenAI API key is required for AI-assisted reporting.")
    key = _prompt_secret("[+] Enter OpenAI API key (starts with 'sk-'):")
    if key:
        cfg["openai_api_key"] = key
        _save_config(cfg)
    return key

def _validate_openai_api_key(key: str) -> bool:
    if not key or len(key) < 20:
        return False
    try:
        req = urllib.request.Request(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            code = getattr(r, "status", None) or r.getcode()
            if int(code) != 200:
                return False
            try:
                data = json.loads(r.read().decode("utf-8", "ignore"))
            except Exception:
                return False
            return isinstance(data, dict) and "data" in data
    except Exception:
        return False

def _require_openai_api_key() -> str:
    cfg = _load_config()
    key = os.getenv("OPENAI_API_KEY") or cfg.get("openai_api_key") or ""
    if key and _validate_openai_api_key(key):
        return key.strip()
    attempts = 0
    while attempts < 3:
        print("[!] OpenAI API key is required for AI-assisted reporting.")
        k = _prompt_secret("[+] Enter OpenAI API key (starts with 'sk-'):")
        if _validate_openai_api_key(k):
            cfg["openai_api_key"] = k
            _save_config(cfg)
            return k
        print("[!] Invalid OpenAI API key; please try again.")
        attempts += 1
    logger.warning("Skipping AI assistance due to invalid OpenAI API key after multiple attempts")
    return ""

def _get_shodan_api_key(interactive: bool = True) -> str:
    env_key = os.getenv("SHODAN_API_KEY")
    if env_key:
        return env_key.strip()
    cfg = _load_config()
    if cfg.get("shodan_api_key"):
        return str(cfg["shodan_api_key"]).strip()
    if not interactive:
        return ""
    print("[!] Shodan API key is required for Shodan CLI/API.")
    key = _prompt_secret("[+] Enter Shodan API key:")
    if key:
        cfg["shodan_api_key"] = key
        _save_config(cfg)
    return key

def _validate_shodan_api_key(key: str) -> bool:
    if not key or len(key) < 10:
        return False
    try:
        url = f"https://api.shodan.io/api-info?key={quote_plus(key)}"
        r = urllib.request.urlopen(url, timeout=10)
        code = getattr(r, "status", None) or r.getcode()
        if int(code) != 200:
            return False
        try:
            data = json.loads(r.read().decode("utf-8", "ignore"))
        except Exception:
            return False
        if isinstance(data, dict) and ("plan" in data or "query_credits" in data):
            return True
        return False
    except Exception:
        return False

def _require_shodan_api_key() -> str:
    cfg = _load_config()
    key = os.getenv("SHODAN_API_KEY") or cfg.get("shodan_api_key") or ""
    if key and _validate_shodan_api_key(key):
        return key.strip()
    attempts = 0
    while attempts < 3:
        print("[!] Shodan API key is required for Shodan CLI/API.")
        k = _prompt_secret("[+] Enter Shodan API key:")
        if _validate_shodan_api_key(k):
            cfg["shodan_api_key"] = k
            _save_config(cfg)
            return k
        print("[!] Invalid Shodan API key; please try again.")
        attempts += 1
    print("[!] Failed to obtain a valid Shodan API key after multiple attempts; exiting.")
    sys.exit(1)

def _extract_json_block(text: str) -> dict:
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        pass
    try:
        import re as _re
        m = _re.search(r"```json\s*(\{[\s\S]*?\})\s*```", text)
        if m:
            return json.loads(m.group(1))
        m = _re.search(r"(\{[\s\S]*\})", text)
        if m:
            return json.loads(m.group(1))
    except Exception:
        pass
    return {}

def ai_assist(case_dir, state):
    api_key = _require_openai_api_key()
    if not api_key:
        print("[!] Skipping AI assistance due to missing/invalid OpenAI API key.")
        return

    recon_dir = case_dir / "recon"
    # Ensure report identity fields are set before composing AI prompt
    try:
        state.setdefault("prepared_by", _get_prepared_by(interactive=False))
        state.setdefault("contact", _get_default_contact(interactive=False))
    except Exception:
        pass
    whois_txt = _read_text(recon_dir / "whois.txt")
    dns_txt = _read_text(recon_dir / "dns.txt")
    headers_txt = _read_text(recon_dir / "headers.txt")
    robots_txt = _read_text(recon_dir / "robots.txt")
    whatweb_txt = _read_text(recon_dir / "whatweb.txt")
    subdomains_txt = _read_text(recon_dir / "subdomains.txt")
    crtsh_txt = _read_text(recon_dir / "crtsh.txt")
    ssl_labs_txt = _read_text(recon_dir / "ssl_labs.txt")
    shodan_txt = _read_text(recon_dir / "shodan.txt")

    sys_prompt = (
        "You are a security analyst. Read passive recon artifacts and infer real security exposures based on common vulnerable patterns "
        "(e.g., missing HSTS, weak/legacy TLS, insecure headers, exposed services/ports, outdated tech, sensitive subdomains). "
        "Produce: area risk levels (use labels Low/Medium/High) for Domain/DNS, Tech Stack, Email/Creds, SSL, Sec Headers; a Key Observations section "
        "(3 to 5 concise items) grounded in the artifacts with short evidence notes; and an overall exposure score 0–100. "
        "Then compose a complete Markdown report that EXACTLY follows these sections and order with plain ASCII only: "
        "title: 'Passive Security Exposure Snapshot'; header lines 'Prepared for: <Business Name>', 'Website: <domain>', 'Date: <date>', 'Prepared by: <prepared_by>'; "
        "sections 1–7: Executive Summary; Exposure Overview; Key Observations (Top 3-5); Exposure Risk Score; Recommended Next Steps; Authorization & Disclosure; Optional Consultation. "
        "Render Exposure Overview as a 3-column markdown table with headers Area | Status | Risk Level and use the exact row labels: "
        "Domain & DNS Configuration, Website Technology Stack, Email & Credential Exposure, SSL / Transport Security, Security Headers. Status must be 'Observed'. "
        "In Executive Summary include only 'Overall Exposure Rating: <Low/Moderate/Elevated/High>' (map score: 0-24 Low, 25-49 Moderate, 50-74 Elevated, 75-100 High). "
        "In Exposure Risk Score include 'Overall Exposure Score: <N>' and the short explanation. "
        "Do NOT include any raw logs, code blocks, or appendices. Be concise (<= 500 words). Use only ASCII characters; replace fancy punctuation with '-' and standard quotes. "
        "Output ONLY JSON with keys: area_ratings (object with keys: domain_dns, tech_stack, email_creds, ssl, sec_headers), observations_md (string), suggested_score (int), report_md (string)."
    )
    user_payload = {
        "business_name": state.get("business_name", ""),
        "domain": state.get("domain", ""),
        "prepared_by": state.get("prepared_by", "Your Business Name"),
        "contact": state.get("contact", "you@company.com"),
        "date": state.get("date", ""),
        "artifacts": {
            "whois": whois_txt,
            "dns": dns_txt,
            "headers": headers_txt,
            "robots": robots_txt,
            "whatweb": whatweb_txt,
            "subdomains": subdomains_txt,
            "crtsh": crtsh_txt,
            "ssl_labs": ssl_labs_txt,
            "shodan": shodan_txt,
        },
    }
    prompt_text = json.dumps(user_payload)

    suggestion = {}
    try:
        models = ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"]
        if _OpenAIClient is not None:
            client = _OpenAIClient(api_key=api_key)
            for m in models:
                try:
                    resp = client.chat.completions.create(
                        model=m,
                        messages=[
                            {"role": "system", "content": sys_prompt},
                            {"role": "user", "content": prompt_text},
                        ],
                        response_format={"type": "json_object"},
                        temperature=0.2,
                    )
                    text = resp.choices[0].message.content
                    suggestion = _extract_json_block(text)
                    if suggestion:
                        break
                except Exception:
                    continue
        elif _openai_mod is not None:
            _openai_mod.api_key = api_key
            for m in models:
                try:
                    resp = _openai_mod.ChatCompletion.create(
                        model=m,
                        messages=[
                            {"role": "system", "content": sys_prompt},
                            {"role": "user", "content": prompt_text},
                        ],
                        response_format={"type": "json_object"},
                        temperature=0.2,
                    )
                    text = resp["choices"][0]["message"]["content"]
                    suggestion = _extract_json_block(text)
                    if suggestion:
                        break
                except Exception:
                    continue
    except Exception:
        logger.exception("OpenAI request failed")
        return

    if not suggestion:
        logger.warning("AI returned no suggestions")
        return

    area = suggestion.get("area_ratings") or {}
    obs_md = suggestion.get("observations_md") or ""
    report_md = suggestion.get("report_md") or ""
    try:
        ai_score = int(suggestion.get("suggested_score"))
    except Exception:
        ai_score = None

    state.setdefault("ai", {})
    state["ai"]["area_ratings"] = area
    state["ai"]["observations_md"] = obs_md
    if report_md:
        state["ai"]["report_md"] = report_md
    if ai_score is not None:
        state["ai"]["suggested_score"] = ai_score
    # Pre-fill if not set
    state.setdefault("area_ratings", area or {})
    if not state.get("observations_md") and obs_md:
        state["observations_md"] = obs_md
    logger.debug("ai_assist(): suggestions applied (area ratings=%s, suggested_score=%s)", area, ai_score)

def _compute_overall_rating(score: int) -> str:
    try:
        s = int(score)
    except Exception:
        s = 0
    if s <= 24:
        return "Low"
    if s <= 49:
        return "Moderate"
    if s <= 74:
        return "Elevated"
    return "High"

def _prompt_choice(msg: str, choices: list, default: str) -> str:
    canon = {c.lower(): c for c in choices}
    synonyms = {
        "low": "Low",
        "l": "Low",
        "med": "Med",
        "m": "Med",
        "medium": "Med",
        "moderate": "Med",
        "high": "High",
        "h": "High",
    }
    prompt_text = f"{msg} [{'/'.join(choices)}] (default {default})"
    while True:
        val = prompt(prompt_text)
        if not val:
            return default
        key = val.strip().lower()
        if key in canon:
            return canon[key]
        if key in synonyms:
            return synonyms[key]
        logger.warning("Invalid choice. Please enter one of: %s", ", ".join(choices))

def report_inputs(case_dir, state):
    logger.debug("Starting report_inputs step")
    prepared_by = state.get("prepared_by") or _get_prepared_by(interactive=False)
    contact = state.get("contact") or _get_default_contact(interactive=False)
    area = state.get("ai", {}).get("area_ratings") or state.get("area_ratings") or {}
    ratings = {
        "domain_dns": area.get("domain_dns", "Medium"),
        "tech_stack": area.get("tech_stack", "Medium"),
        "email_creds": area.get("email_creds", "Medium"),
        "ssl": area.get("ssl", "Medium"),
        "sec_headers": area.get("sec_headers", "Medium"),
    }
    observations_md = state.get("ai", {}).get("observations_md") or state.get("observations_md") or ""
    state["prepared_by"] = prepared_by
    state["contact"] = contact
    state["area_ratings"] = ratings
    if observations_md:
        state["observations_md"] = observations_md
    logger.debug("report_inputs(): auto-populated without prompts")

# =========================
# GOOGLE INTEGRATIONS (optional)
# =========================

def _get_google_credentials():
    if _InstalledAppFlow is None or _GoogleCredentials is None or _GoogleRequest is None:
        logger.warning("Google API libraries not installed; skipping Google integration")
        return None
    cfg = _load_config()
    if GOOGLE_TOKEN_FILE.exists():
        try:
            creds = _GoogleCredentials.from_authorized_user_file(str(GOOGLE_TOKEN_FILE), GOOGLE_SCOPES)
        except Exception:
            creds = None
    else:
        creds = None
    if creds and creds.valid:
        return creds
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(_GoogleRequest())
            GOOGLE_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
            GOOGLE_TOKEN_FILE.write_text(creds.to_json())
            return creds
        except Exception:
            logger.exception("Failed to refresh Google credentials; will re-auth")
    client_path = cfg.get("google_client_secret_path")
    # Validate existing path or re-prompt until a valid file is provided (blank to abort)
    attempts = 0
    while True:
        if client_path and Path(client_path).is_file():
            break
        print("[!] Google OAuth client secrets JSON is required (download from Google Cloud Console)")
        if client_path and Path(client_path).exists() and Path(client_path).is_dir():
            print("[!] The path you provided is a directory. Please provide the full path to the JSON file (e.g., /path/client_secret.json).")
        p = prompt("Path to client_secret.json (leave blank to skip)")
        p = (p or "").strip()
        if not p:
            logger.warning("No Google client secrets provided; skipping Google integration")
            return None
        p = str(Path(p).expanduser())
        if not Path(p).is_file():
            print("[!] That path is not a file or does not exist. Try again.")
            client_path = p
            attempts += 1
            if attempts >= 3:
                logger.warning("Max attempts reached for client_secret.json path; skipping Google integration")
                return None
            continue
        cfg["google_client_secret_path"] = p
        _save_config(cfg)
        client_path = p
    # Attempt OAuth flow; if directory/file errors occur, re-prompt once
    try:
        flow = _InstalledAppFlow.from_client_secrets_file(client_path, GOOGLE_SCOPES)
        creds = _google_run_oauth_flow(flow)
        GOOGLE_TOKEN_FILE.parent.mkdir(parents=True, exist_ok=True)
        GOOGLE_TOKEN_FILE.write_text(creds.to_json())
        return creds
    except IsADirectoryError:
        print("[!] Provided path is a directory. Please provide the full JSON file path.")
    except FileNotFoundError:
        print("[!] Provided client_secret.json path not found. Please provide a valid file path.")
    except Exception:
        logger.exception("Google OAuth failed")
        return None
    # Re-prompt once more after specific errors
    cfg["google_client_secret_path"] = ""
    _save_config(cfg)
    return _get_google_credentials()

def _get_google_services():
    if _gbuild is None:
        return None, None, None
    creds = _get_google_credentials()
    if not creds:
        return None, None, None
    try:
        drive = _gbuild('drive', 'v3', credentials=creds)
        docs = _gbuild('docs', 'v1', credentials=creds)
        sheets = _gbuild('sheets', 'v4', credentials=creds)
        return drive, docs, sheets
    except Exception:
        logger.exception("Failed to build Google API services")
        return None, None, None

def setup_google_integration_interactive():
    logger.debug("setup_google_integration_interactive(): starting")
    if _gbuild is None:
        print("[!] Google API libraries are not installed.")
        print("[i] Please install: pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib")
        return
    cfg = _load_config()
    path = cfg.get("google_client_secret_path")
    if not path or not Path(path).is_file():
        # Loop until a valid file is provided or user skips
        while True:
            p = prompt("Path to Google OAuth client_secret.json (leave blank to skip)")
            p = (p or "").strip()
            if not p:
                break
            p = str(Path(p).expanduser())
            if Path(p).is_file():
                cfg["google_client_secret_path"] = p
                _save_config(cfg)
                path = p
                break
            if Path(p).exists() and Path(p).is_dir():
                print("[!] That path is a directory. Provide the full JSON file path.")
            else:
                print("[!] Provided path does not exist or is not a file. Try again.")
    # Trigger OAuth flow now so future runs are seamless
    d, dc, sh = _get_google_services()
    if not d or not dc or not sh:
        print("[!] Google authorization not completed; please check your client_secret.json and try again.")
        return
    # Ask for Drive clients root name
    root_name = cfg.get('drive_clients_root_name') or 'Clients'
    if yes_no(f"Use '{root_name}' as the Drive root folder for client deliverables?"):
        cfg['drive_clients_root_name'] = root_name
    else:
        rn = prompt("Enter Drive root folder name (e.g., Clients)")
        if rn:
            cfg['drive_clients_root_name'] = rn.strip()
    # Optionally store sheet id/name
    if yes_no("Store Google Sheet ID and Sheet name for batch processing?"):
        sid = prompt("Google Sheet ID")
        sname = prompt("Sheet name (tab)")
        if sid:
            cfg['google_sheet_id'] = sid.strip()
        if sname:
            cfg['google_sheet_name'] = sname.strip()
    _save_config(cfg)
    print("[+] Google integrations configured")

def _google_config_ready():
    if _gbuild is None:
        return False
    cfg = _load_config()
    p = cfg.get("google_client_secret_path")
    return bool(p and Path(p).is_file() and GOOGLE_TOKEN_FILE.exists())

def _google_run_oauth_flow(flow):
    """Run OAuth flow with a browser if available, otherwise fall back to console.
    Users can force console-based flow by setting SECOPS_GOOGLE_CONSOLE_FLOW=1.
    """
    prefer_console = str(os.getenv("SECOPS_GOOGLE_CONSOLE_FLOW", "")).strip().lower() in {"1", "true", "yes"}
    headless = bool(os.getenv("WSL_DISTRO_NAME")) and shutil.which("xdg-open") is None
    if prefer_console or headless:
        print("[i] Using console-based OAuth flow. Copy the URL, authorize, and paste the code.")
        return flow.run_console()
    try:
        return flow.run_local_server(port=0)
    except Exception:
        print("[!] Browser-based OAuth failed. Falling back to console copy-paste flow.")
        return flow.run_console()

def _drive_ensure_folder(drive, name, parent_id=None):
    try:
        q = f"name = '{name.replace("'", "\\'")}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
        if parent_id:
            q += f" and '{parent_id}' in parents"
        res = drive.files().list(q=q, spaces='drive', fields='files(id, name, parents)').execute()
        items = res.get('files', [])
        if items:
            return items[0]['id']
        meta = {'name': name, 'mimeType': 'application/vnd.google-apps.folder'}
        if parent_id:
            meta['parents'] = [parent_id]
        folder = drive.files().create(body=meta, fields='id').execute()
        return folder['id']
    except Exception:
        logger.exception("drive ensure folder failed")
        return None

def _drive_get_or_create_clients_root(drive):
    cfg = _load_config()
    root_name = cfg.get('drive_clients_root_name') or 'Clients'
    return _drive_ensure_folder(drive, root_name)

def _drive_find_child_by_name(drive, parent_id, name):
    try:
        q = f"name = '{name.replace("'", "\\'")}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false and '{parent_id}' in parents"
        res = drive.files().list(q=q, spaces='drive', fields='files(id, name)').execute()
        items = res.get('files', [])
        return items[0]['id'] if items else None
    except Exception:
        logger.exception("drive find child failed")
        return None

def _drive_get_or_create_client_folder(drive, clients_root_id, domain, business_name, mapping: dict):
    # Priority: mapping override -> exact business -> title-cased business -> domain -> domain base
    candidates = []
    if mapping and domain in mapping:
        candidates.append(mapping[domain])
    if business_name:
        candidates.append(business_name)
        candidates.append(str(business_name).title())
    if domain:
        candidates.append(domain)
        base = domain.split(".")[0]
        candidates.append(base)
        candidates.append(base.title())
    seen = set()
    for name in candidates:
        name = (name or "").strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        fid = _drive_find_child_by_name(drive, clients_root_id, name)
        if fid:
            return fid, name
    # Not found: create using best candidate
    target = None
    for n in candidates:
        if n and n.strip():
            target = n.strip()
            break
    target = target or (business_name or domain or "Client")
    fid = _drive_ensure_folder(drive, target, parent_id=clients_root_id)
    return fid, target

def _docs_create_in_folder(docs, drive, folder_id, title, text_content):
    try:
        doc = docs.documents().create(body={'title': title}).execute()
        doc_id = doc.get('documentId')
        try:
            drive.files().update(fileId=doc_id, addParents=folder_id, fields='id, parents').execute()
        except Exception:
            pass
        try:
            docs.documents().batchUpdate(documentId=doc_id, body={
                'requests': [
                    {'insertText': {'location': {'index': 1}, 'text': text_content}}
                ]
            }).execute()
        except Exception:
            logger.exception("docs insert text failed")
        return doc_id
    except Exception:
        logger.exception("docs create failed")
        return None

def _drive_upload_pdf_bytes(drive, folder_id, name, data: bytes):
    try:
        media = _MediaIoBaseUpload(io.BytesIO(data), mimetype='application/pdf', resumable=False)
        file = drive.files().create(body={'name': name, 'parents': [folder_id]}, media_body=media, fields='id').execute()
        return file.get('id')
    except Exception:
        logger.exception("drive pdf upload failed")
        return None

def _docs_export_pdf_and_upload(drive, doc_id, folder_id, pdf_name):
    try:
        data = drive.files().export(fileId=doc_id, mimeType='application/pdf').execute()
        if isinstance(data, bytes):
            pdf_bytes = data
        else:
            pdf_bytes = data if hasattr(data, 'decode') else bytes(data)
        return _drive_upload_pdf_bytes(drive, folder_id, pdf_name, pdf_bytes)
    except Exception:
        logger.exception("export pdf failed")
        return None

def _drive_upload_file(drive, folder_id, local_path, name=None, mime_type='application/octet-stream'):
    try:
        if not _MediaFileUpload:
            logger.warning("MediaFileUpload unavailable; cannot upload %s", local_path)
            return None
        lp = str(local_path)
        nm = name or os.path.basename(lp)
        media = _MediaFileUpload(lp, mimetype=mime_type, resumable=False)
        file = drive.files().create(body={'name': nm, 'parents': [folder_id]}, media_body=media, fields='id').execute()
        return file.get('id')
    except Exception:
        logger.exception("drive file upload failed for %s", local_path)
        return None

def _col_letter(idx_zero_based):
    n = idx_zero_based + 1
    s = ''
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s

def _should_auto_batch() -> bool:
    try:
        if _gbuild is None:
            return False
        cfg = _load_config()
        auto = str(cfg.get("auto_batch", "")).strip().lower() in {"1", "true", "yes"}
        if auto:
            return True
        # Default to batch if Google is fully configured and a Sheet is saved
        if _google_config_ready() and cfg.get("google_sheet_id") and cfg.get("google_sheet_name"):
            return True
    except Exception:
        return False
    return False

def _print_help_extended():
    try:
        txt = f"""
Passive Security Exposure Snapshot - Extended Help

USAGE
- Single-case interactive (default):
  python secops_snapshot.py

- Batch from Google Sheet (no single-case prompts):
  python secops_snapshot.py --batch
  or set environment variable SECOPS_BATCH=1

MAIN OUTPUTS
- Case directory: {CLIENTS_DIR}/<client>
- Report markdown: <case>/reports/report.md and ./<client>_report.md
- Report PDF (if pandoc installed): <case>/reports/report.pdf and ./<client>_report.pdf
- Full artifacts and run log: <case>/reports/report_full_logs.txt

CONFIG AND STATE
- Config file: {CONFIG_FILE}
- Outreach log (email timestamps): {OUTREACH_LOG_FILE}
- Google OAuth token: {GOOGLE_TOKEN_FILE}

GOOGLE INTEGRATION (Drive/Docs/Sheets)
- First-time setup will store:
  google_client_secret_path, google_sheet_id, google_sheet_name, drive_clients_root_name
- Requirements: pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib
- To re-auth: delete {GOOGLE_TOKEN_FILE} and rerun setup

EMAIL SENDING
- After report generation, you can send an initial outreach email attaching the PDF.
- SMTP settings are stored under 'email_smtp' in {CONFIG_FILE} (host, port, username, from_email, from_name, optional password).
- Follow-ups are sent based on timestamps in {OUTREACH_LOG_FILE}:
  - Follow-up 1 after 48 hours
  - Final follow-up after 72 hours from follow-up 1

SHODAN INTEGRATION
- Requires a valid key; stored as shodan_api_key in config when provided.
- Uses 'shodan' CLI if initialized, else falls back to HTTP API.

OPENAI (optional, for AI-assisted report composition)
- OPENAI_API_KEY is required when using AI assistance; key is stored in config once validated.

CLI FLAGS
- --batch                 Run Google Sheets batch processing and exit
- --artifact-mode MODE    none | relevant | full (default relevant)
- --shodan-include MODE   summary | excerpt | full (default excerpt)
- --shodan-excerpt-lines N  number of lines for Shodan excerpt (default 25)
- --help                  Show basic argparse help
- --help-all              Show this extended help

ENVIRONMENT VARIABLES
- SECOPS_BATCH=1                Run in batch mode automatically
- SECOPS_DEBUG=1 or SECOPS_LOG_LEVEL=LEVEL (INFO, DEBUG, etc.)
- SECOPS_ARTIFACT_MODE=none|relevant|full
- SECOPS_INCLUDE_APPENDICES=1   Force full appendices
- SECOPS_VISIBLE_INPUT=1        Make secret prompts visible (fallback)
- SECOPS_GOOGLE_CONSOLE_FLOW=1  Use console OAuth flow instead of browser
- OPENAI_API_KEY, SHODAN_API_KEY

TIPS
- Store Google Sheet and OAuth once; subsequent runs won’t prompt again.
- Use --batch for lead sheet processing; single-case prompts are only for interactive mode.
"""
        print(txt)
    except Exception:
        # Fallback minimal help if printing fails
        print("Extended help unavailable due to an error.")

def process_batch_from_google_sheet(interactive: bool = True):
    drive, docs, sheets = _get_google_services()
    if not drive or not docs or not sheets:
        logger.warning("Google services unavailable; aborting batch mode")
        return
    cfg = _load_config()
    sheet_id = cfg.get("google_sheet_id")
    sheet_name = cfg.get("google_sheet_name")
    # Ensure prepared_by and default contact are stored once
    _ = _get_prepared_by(interactive=interactive)
    _ = _get_default_contact(interactive=interactive)
    if not sheet_id:
        if interactive:
            sheet_id = prompt("Google Sheet ID")
            cfg["google_sheet_id"] = sheet_id
            _save_config(cfg)
        else:
            logger.warning("google_sheet_id not set; cannot run batch non-interactively")
            return
    if not sheet_name:
        if interactive:
            sheet_name = prompt("Sheet name (tab)")
            cfg["google_sheet_name"] = sheet_name
            _save_config(cfg)
        else:
            logger.warning("google_sheet_name not set; cannot run batch non-interactively")
            return
    clients_root_id = _drive_get_or_create_clients_root(drive)
    try:
        resp = sheets.spreadsheets().values().get(spreadsheetId=sheet_id, range=f"{sheet_name}!A:Z").execute()
        rows = resp.get('values', [])
    except Exception:
        logger.exception("Failed to read Google Sheet")
        return
    if not rows:
        logger.warning("Sheet has no rows")
        return
    header = [c.strip() for c in rows[0]]
    cols = {name.lower(): i for i, name in enumerate(header)}
    req_cols = ['website', 'e-mail', 'report generated', 'emailed']
    for rc in req_cols:
        if rc not in cols:
            logger.warning("Missing required column: %s", rc)
            return
    website_idx = cols['website']
    email_idx = cols['e-mail']
    gen_idx = cols['report generated']
    emailed_idx = cols['emailed']
    for r_idx in range(1, len(rows)):
        row = rows[r_idx]
        def get(i):
            return row[i].strip() if i < len(row) and row[i] else ''
        website = get(website_idx)
        email = get(email_idx)
        gen = get(gen_idx).lower()
        emailed_flag = get(emailed_idx).lower()
        if not website:
            print(f"[-] Row {r_idx+1}: missing website; skipping")
            continue
        print(f"[>] Row {r_idx+1}: {website} | email={email or '-'} | gen={gen or '-'} | emailed={emailed_flag or '-'}")
        if gen == 'y' and emailed_flag == 'y':
            print(f"[-] {website}: already generated and emailed; skipping")
            continue
        domain = _normalize_domain(website)
        # Resolve display business name from config mapping (fallback to domain)
        cfg_names = (_load_config().get('business_names') or {})
        business = cfg_names.get(domain) or domain
        client = _safe_slug(domain)
        skip_recon = (gen == 'y')
        if skip_recon:
            print(f"[=] Report already generated for {domain}; skipping recon and regeneration")
            case_dir = CLIENTS_DIR / client
            # Minimal state for emailing and context
            state = {
                "client": client,
                "business_name": business,
                "domain": domain,
                "date": str(datetime.date.today()),
            }
        else:
            case_dir, state = init_case_with_inputs(client, domain, business)
            # Do not persist or rely on per-row email; use user's default contact for reports
            state['contact'] = state.get('contact') or _get_default_contact(interactive=False)
            prepared_by = _get_prepared_by(interactive=False)
            state['prepared_by'] = prepared_by
            print(f"[.] Recon: whois for {domain}")
            whois_lookup(case_dir, state)
            print(f"[.] Recon: dns for {domain}")
            dns_lookup(case_dir, state)
            print(f"[.] Recon: headers for {domain}")
            headers_check(case_dir, state)
            print(f"[.] Recon: robots for {domain}")
            robots_check(case_dir, state)
            print(f"[.] Recon: whatweb for {domain}")
            whatweb_scan(case_dir, state)
            print(f"[.] Recon: subdomains for {domain}")
            subdomain_enum(case_dir, state)
            print(f"[.] Recon: crt.sh for {domain}")
            crtsh_lookup(case_dir, state)
            print(f"[.] TLS probe for {domain}")
            ssl_tls_probe(case_dir, state)
            print(f"[.] Shodan for {domain}")
            shodan_lookup(case_dir, state)
            print(f"[.] AI assist for {domain}")
            ai_assist(case_dir, state)
            print(f"[.] Report inputs for {domain}")
            report_inputs(case_dir, state)
            print(f"[.] Risk scoring for {domain}")
            risk_scoring(case_dir, state)
            print(f"[.] Generating report for {domain}")
            generate_report(case_dir, state)
        try:
            with open(case_dir / 'reports' / 'report.md', 'r', encoding='utf-8', errors='ignore') as f:
                report_text = f.read()
        except Exception:
            report_text = ''
        # Resolve folder and upload only when generating a new report
        if not skip_recon:
            cfg = _load_config()
            mapping = (cfg.get('drive_folder_names') or {})
            folder_id, folder_name = _drive_get_or_create_client_folder(
                drive, clients_root_id, domain, state.get('business_name'), mapping
            )
        else:
            folder_id, folder_name = (None, None)
        if folder_id and not skip_recon:
            title = f"{folder_name} Passive Security Exposure Snapshot"
            doc_id = _docs_create_in_folder(docs, drive, folder_id, title, report_text)
            if doc_id:
                _docs_export_pdf_and_upload(drive, doc_id, folder_id, f"{folder_name}.pdf")
            try:
                full_txt_path = case_dir / 'reports' / 'report_full_logs.txt'
                if full_txt_path.exists():
                    _drive_upload_file(drive, folder_id, str(full_txt_path), name='report_full_logs.txt', mime_type='text/plain')
            except Exception:
                logger.exception("Failed to upload report_full_logs.txt to Drive")
            print(f"[+] Uploaded to Drive folder '{folder_name}' for {domain}")
        sent_initial = False
        try:
            if email and emailed_flag != 'y':
                print(f"[.] Sending email to {email} for {domain}")
                sent_initial = send_outreach_post_report(
                    case_dir,
                    state,
                    email,
                    recipient_name=state.get('business_name'),
                    interactive=interactive,
                )
        except Exception:
            logger.exception("Batch email send failed for %s", state.get('domain'))
            print(f"[!] Email send raised exception for {domain}")
        if not skip_recon:
            try:
                col_letter = _col_letter(gen_idx)
                cell_range = f"{sheet_name}!{col_letter}{r_idx+1}"
                sheets.spreadsheets().values().update(
                    spreadsheetId=sheet_id,
                    range=cell_range,
                    valueInputOption='RAW',
                    body={'values': [[ 'y' ]]}
                ).execute()
                print(f"[+] Marked Report Generated = y for {website}")
            except Exception:
                logger.exception("Failed to update Report Generated for row %s", r_idx+1)
                print(f"[!] Failed to update Report Generated for {website}")
        else:
            print(f"[=] Report Generated already y for {website}; no update needed")
        try:
            if sent_initial:
                col_letter_e = _col_letter(emailed_idx)
                cell_range_e = f"{sheet_name}!{col_letter_e}{r_idx+1}"
                sheets.spreadsheets().values().update(
                    spreadsheetId=sheet_id,
                    range=cell_range_e,
                    valueInputOption='RAW',
                    body={'values': [[ 'y' ]]}
                ).execute()
                print(f"[+] Marked Emailed = y for {website}")
            else:
                if emailed_flag == 'y':
                    print(f"[-] Emailed already y for {website}")
                else:
                    print(f"[!] Email not sent for {website}; leaving Emailed blank")
        except Exception:
            logger.exception("Failed to update Emailed for row %s", r_idx+1)
            print(f"[!] Failed to update Emailed for {website}")

def init_case_with_inputs(client: str, domain: str, business: str):
    logger.debug("init_case_with_inputs(): starting")
    norm_domain = _normalize_domain(domain)
    safe_client = _safe_slug(client)
    case_dir = CLIENTS_DIR / safe_client
    for d in ["scope", "recon", "scans", "evidence", "reports", "notes"]:
        (case_dir / d).mkdir(parents=True, exist_ok=True)
    scope_file = case_dir / "scope" / "scope.txt"
    scope_file.write_text(
        f"Domain: {domain}\n"
        "Scope: Passive analysis only\n"
        "No authentication, exploitation, or active scanning\n"
    )
    state = {
        "client": client,
        "business_name": business,
        "domain": norm_domain,
        "date": str(datetime.date.today()),
        "checklist": CHECKLIST_ITEMS.copy(),
        "findings": [],
        "risk_score": 0
    }
    with open(case_dir / "notes" / "state.json", "w") as f:
        json.dump(state, f, indent=2)
    logger.debug("init_case_with_inputs(): initialized (client=%s, domain=%s)", client, norm_domain)
    return case_dir, state
# =========================
# CASE INITIALIZATION
# CHECKLIST: (none)
#BMGD5KD6XEBYR8HDP7Z9HQUM
# =========================

def init_case():
    logger.debug("init_case(): starting")
    auto = os.getenv("SECOPS_AUTO") or os.getenv("SECOPS_NON_INTERACTIVE")
    if auto:
        client = os.getenv("SECOPS_CLIENT") or "client"
        domain = os.getenv("SECOPS_DOMAIN") or "example.com"
        business = os.getenv("SECOPS_BUSINESS") or client
    else:
        client = prompt("Client short name (e.g. acme_corp)")
        domain = prompt("Primary domain (example.com)")
        business = prompt("Business legal name")

    # Normalize inputs
    norm_domain = _normalize_domain(domain)
    safe_client = _safe_slug(client)

    case_dir = CLIENTS_DIR / safe_client
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
        "domain": norm_domain,
        "date": str(datetime.date.today()),
        "checklist": CHECKLIST_ITEMS.copy(),
        "findings": [],
        "risk_score": 0
    }

    with open(case_dir / "notes" / "state.json", "w") as f:
        json.dump(state, f, indent=2)
    logger.debug("init_case(): state written to %s", case_dir / "notes" / "state.json")
    logger.debug("init_case(): initialized (client=%s -> %s, domain=%s -> %s, date=%s)", client, safe_client, domain, norm_domain, state["date"])
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
    timeout = int(os.getenv("SECOPS_TIMEOUT_WHATWEB", "240"))
    run_cmd(f"whatweb -a 3 https://{state['domain']}", out, desc="whatweb", timeout=timeout)
    state["checklist"]["tech_stack"] = True
    logger.debug("whatweb_scan(): complete")

def subdomain_enum(case_dir, state):
    logger.debug("Starting subdomain_enum for domain %s", state["domain"])
    # CHECKLIST: subdomains
    out = case_dir / "recon" / "subdomains.txt"
    logger.debug("subdomain_enum(): writing to %s", out)
    timeout = int(os.getenv("SECOPS_TIMEOUT_SUBFINDER", "300"))
    run_cmd(f"subfinder -d {state['domain']} -silent", out, desc="subfinder", timeout=timeout)
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
# MANUAL / OPTIONAL INPUT PHASE
# =========================

def ssl_tls_probe(case_dir, state):
    logger.debug("Starting ssl_tls_probe step")
    out = case_dir / "recon" / "ssl_labs.txt"
    host = state["domain"]
    lines = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                try:
                    ver = ssock.version() or ""
                except Exception:
                    ver = ""
                try:
                    cipher = ssock.cipher()
                except Exception:
                    cipher = None
                try:
                    cert = ssock.getpeercert()
                except Exception:
                    cert = {}
                lines.append(f"TLS_Version: {ver}")
                if cipher:
                    name, proto, bits = cipher[0], cipher[1], cipher[2] if len(cipher) > 2 else ""
                    lines.append(f"Cipher: {name} ({bits} bits)")
                subj = dict(x[0] for x in cert.get('subject', ())) if cert else {}
                issr = dict(x[0] for x in cert.get('issuer', ())) if cert else {}
                lines.append(f"Subject_CN: {subj.get('commonName','')}")
                lines.append(f"Issuer_CN: {issr.get('commonName','')}")
                lines.append(f"NotBefore: {cert.get('notBefore','')}")
                lines.append(f"NotAfter: {cert.get('notAfter','')}")
    except Exception:
        logger.exception("ssl_tls_probe(): TLS probe failed for %s", host)
        lines.append("probe_error: true")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    (case_dir / "recon" / "ssl_labs.txt").write_text("\n".join(lines))
    state["checklist"]["ssl"] = True
    logger.debug("ssl_tls_probe(): wrote to %s", out)

def manual_ssl(case_dir, state):
    logger.debug("Starting manual_ssl step")
    # Default to automated TLS probe to avoid manual input
    return ssl_tls_probe(case_dir, state)

def manual_shodan(case_dir, state):
    logger.debug("Starting manual_shodan step")
    # CHECKLIST: shodan
    print("[!] Manual Step: Shodan search hostname")
    notes = prompt_multiline("Paste Shodan findings")
    (case_dir / "recon" / "shodan.txt").write_text(notes)
    state["checklist"]["shodan"] = True
    logger.debug("manual_shodan(): notes saved to %s", case_dir / "recon" / "shodan.txt")

def shodan_lookup(case_dir, state):
    logger.debug("Starting shodan_lookup for domain %s", state["domain"])
    out = case_dir / "recon" / "shodan.txt"
    query = f'hostname:"{state["domain"]}"'
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    # Require a valid Shodan API key up front; exit after repeated invalid attempts
    key = _require_shodan_api_key()
    try:
        # Ensure Shodan CLI is initialized; prompt to init if needed
        try:
            info = subprocess.run(["shodan", "info"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except Exception:
            info = None
        use_cli = bool(info and info.returncode == 0)
        if (not use_cli):
            try:
                if yes_no("Shodan CLI appears uninitialized. Initialize now?"):
                    subprocess.run(["shodan", "init", key], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    info = subprocess.run(["shodan", "info"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    use_cli = bool(info and info.returncode == 0)
            except Exception:
                use_cli = False

        result = subprocess.CompletedProcess(args=[], returncode=0)
        ips = set()
        if use_cli:
            with open(out, "w", encoding="utf-8", errors="ignore") as f:
                result = subprocess.run([
                    "shodan", "search", "--limit", "100", query
                ], stdout=f, stderr=subprocess.STDOUT, text=True)
            logger.debug("shodan_lookup(): return code %s", getattr(result, "returncode", None))
            if result.returncode != 0:
                logger.warning("shodan search returned non-zero exit code: %s", result.returncode)
            # Also capture domain overview and host details for resolved IPs
            with open(out, "a", encoding="utf-8", errors="ignore") as f:
                f.write("\n\n===== shodan domain =====\n")
                try:
                    subprocess.run(["shodan", "domain", state["domain"]], stdout=f, stderr=subprocess.STDOUT, text=True)
                except Exception:
                    pass
                # Resolve A/AAAA records and query host info per IP
                f.write("\n\n===== shodan host (resolved IPs) =====\n")
                try:
                    for family in (socket.AF_INET, socket.AF_INET6):
                        try:
                            infos = socket.getaddrinfo(state["domain"], None, family, socket.SOCK_STREAM)
                            for info in infos:
                                ip = info[4][0]
                                ips.add(ip)
                        except Exception:
                            continue
                except Exception:
                    pass
                for ip in sorted(ips):
                    f.write(f"\n----- {ip} -----\n")
                    try:
                        subprocess.run(["shodan", "host", ip], stdout=f, stderr=subprocess.STDOUT, text=True)
                    except Exception:
                        continue
        # Fallback via HTTP API if CLI is unavailable, returned access denied, or failed
        needs_http = (not use_cli)
        try:
            content = _read_text(out)
            if ("403 Forbidden" in content) or ("Access denied" in content) or (getattr(result, "returncode", 0) not in (None, 0)):
                needs_http = True
        except Exception:
            needs_http = True
        if needs_http:
            with open(out, "a" if use_cli else "w", encoding="utf-8", errors="ignore") as f:
                if not use_cli:
                    f.write("[i] Shodan CLI unavailable or uninitialized; using HTTP API.\n")
                f.write("\n\n===== shodan HTTP API search =====\n")
                try:
                    url = f"https://api.shodan.io/shodan/host/search?key={key}&query={quote_plus(query)}"
                    r = urllib.request.urlopen(url, timeout=30)
                    f.write(r.read().decode("utf-8", "ignore"))
                except Exception as e:
                    f.write(f"HTTP API search error: {e}\n")
                f.write("\n\n===== shodan HTTP API domain =====\n")
                try:
                    url = f"https://api.shodan.io/dns/domain/{state['domain']}?key={key}"
                    r = urllib.request.urlopen(url, timeout=30)
                    f.write(r.read().decode("utf-8", "ignore"))
                except Exception as e:
                    f.write(f"HTTP API domain error: {e}\n")
                # Host info per IP (reuse previously resolved ips)
                try:
                    if not ips:
                        for family in (socket.AF_INET, socket.AF_INET6):
                            try:
                                infos = socket.getaddrinfo(state["domain"], None, family, socket.SOCK_STREAM)
                                for info in infos:
                                    ip = info[4][0]
                                    ips.add(ip)
                            except Exception:
                                continue
                    for ip in sorted(ips):
                        f.write(f"\n----- {ip} (HTTP API) -----\n")
                        try:
                            url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
                            r = urllib.request.urlopen(url, timeout=30)
                            f.write(r.read().decode("utf-8", "ignore"))
                        except Exception as e:
                            f.write(f"HTTP API host error for {ip}: {e}\n")
                except Exception as e:
                    f.write(f"HTTP API host enumeration error: {e}\n")
    except Exception:
        logger.exception("Error running Shodan CLI search")
    state["checklist"]["shodan"] = True
    logger.debug("shodan_lookup(): wrote to %s", out)

def upload_screenshots(case_dir, state):
    logger.debug("Starting upload_screenshots step")
    # CHECKLIST: screenshots
    if os.getenv("SECOPS_AUTO") or os.getenv("SECOPS_NON_INTERACTIVE"):
        logger.debug("upload_screenshots(): auto mode skipping screenshot prompt")
        return
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
    try:
        score = int(state.get("ai", {}).get("suggested_score"))
    except Exception:
        score = None
    if score is None:
        score = 50
    state["risk_score"] = score
    state["checklist"]["risk_score"] = True
    logger.debug("risk_scoring(): set risk_score=%s", score)

# =========================
# REPORT GENERATION
# =========================

def generate_report(case_dir, state):
    logger.debug("Starting generate_report step")
    # CHECKLIST: report_generated
    # Collect artifacts
    recon_dir = case_dir / "recon"
    whois_txt = _read_text(recon_dir / "whois.txt")
    dns_txt = _read_text(recon_dir / "dns.txt")
    headers_txt = _read_text(recon_dir / "headers.txt")
    robots_txt = _read_text(recon_dir / "robots.txt")
    whatweb_txt = _read_text(recon_dir / "whatweb.txt")
    subdomains_txt = _read_text(recon_dir / "subdomains.txt")
    crtsh_txt = _read_text(recon_dir / "crtsh.txt")
    ssl_labs_txt = _read_text(recon_dir / "ssl_labs.txt")
    shodan_txt = _read_text(recon_dir / "shodan.txt")

    # Checklist summary
    ck = state.get("checklist", {})
    def ck_mark(k):
        return "[x]" if ck.get(k) else "[ ]"

    checklist_md = "\n".join([
        f"- {ck_mark('whois')} WHOIS",
        f"- {ck_mark('dns')} DNS",
        f"- {ck_mark('headers')} HTTP Headers",
        f"- {ck_mark('robots')} robots.txt",
        f"- {ck_mark('tech_stack')} WhatWeb",
        f"- {ck_mark('subdomains')} Subdomains",
        f"- {ck_mark('crtsh')} crt.sh",
        f"- {ck_mark('ssl')} SSL/TLS",
        f"- {ck_mark('shodan')} Shodan",
        f"- {ck_mark('screenshots')} Screenshots",
        f"- {ck_mark('risk_score')} Risk Score",
        f"- {ck_mark('report_generated')} Report Generated",
    ])

    # Build base report: prefer AI-composed report if available
    ai_report = (state.get("ai", {}) or {}).get("report_md", "")
    prepared_by = state.get("prepared_by", "Your Business Name")
    contact = state.get("contact", "you@company.com")
    score = int(state.get("risk_score", 0) or 0)
    overall_rating = state.get("overall_rating") or _compute_overall_rating(score)
    area = state.get("area_ratings", {})

    if ai_report.strip():
        report = ai_report
    else:
        report = REPORT_TEMPLATE
        replacements = {
            "{{Business Name}}": state.get("business_name", ""),
            "{{domain}}": state.get("domain", ""),
            "{{date}}": state.get("date", ""),
            "{{Your Business Name}}": prepared_by,
            "{{Overall Exposure Rating}}": overall_rating,
            "{{Overall Exposure Score}}": f"{score} / 100",
            "{{Area_Domain_DNS}}": area.get("domain_dns", "Medium"),
            "{{Area_Tech_Stack}}": area.get("tech_stack", "Medium"),
            "{{Area_Email_Creds}}": area.get("email_creds", "Medium"),
            "{{Area_SSL}}": area.get("ssl", "Medium"),
            "{{Area_Sec_Headers}}": area.get("sec_headers", "Medium"),
            "{{contact}}": contact,
            "{{observations_section}}": (state.get("observations_md") or "(none provided)")
        }
        for k, v in replacements.items():
            report = report.replace(k, v)

    # Artifact inclusion mode: none | relevant | full
    # - none: no appendices (minimal report)
    # - relevant (default): include concise excerpts mapped to observed risks/observations
    # - full: include all artifacts and run log
    mode_env = (os.getenv("SECOPS_ARTIFACT_MODE", "").strip().lower())
    include_full_flag = (os.getenv("SECOPS_INCLUDE_APPENDICES", "").strip().lower() in ("1", "true", "yes"))
    # Prefer mode set in state (CLI-selected), then env toggles, default to 'relevant'
    artifact_mode = (state.get("artifact_mode") or ("full" if include_full_flag else (mode_env or "relevant")))

    def subsection(title, body):
        body = (body or "").strip() or "(no data)"
        return f"\n\n### {title}\n\n```\n{body}\n```\n"

    if artifact_mode == "full":
        appendix = "\n\n## Appendix A: Recon Artifacts\n"
        appendix += subsection("WHOIS", whois_txt)
        appendix += subsection("DNS (dig)", dns_txt)
        appendix += subsection("HTTP Headers", headers_txt)
        appendix += subsection("robots.txt", robots_txt)
        appendix += subsection("WhatWeb", whatweb_txt)
        appendix += subsection("Subdomains (subfinder)", subdomains_txt)
        appendix += subsection("crt.sh", crtsh_txt)
        appendix += subsection("SSL/TLS", ssl_labs_txt)
        # Shodan inclusion honoring user preference
        _incl = (state.get("shodan_include") or "excerpt").lower()
        if _incl == "full":
            appendix += subsection("Shodan", shodan_txt)
        elif _incl == "summary":
            appendix += subsection("Shodan (summary)", _summarize_shodan_text(shodan_txt))
        else:
            appendix += subsection("Shodan (summary)", _summarize_shodan_text(shodan_txt))
            _lines = int(state.get("shodan_excerpt_lines") or 50)
            appendix += subsection("Shodan (excerpt)", "\n".join(shodan_txt.splitlines()[:_lines]))
        logs = "\n".join(getattr(_log_memory_handler, "records", []))
        appendix += "\n\n## Appendix B: Run Log\n"
        appendix += subsection("Run Log", logs)
        report += appendix
    elif artifact_mode != "none":
        # Relevant: choose excerpts based on area ratings and observation keywords
        obs_text = (state.get("observations_md") or "") + "\n" + (state.get("ai", {}).get("observations_md") or "")
        def _has_terms(text, terms):
            t = (text or "").lower()
            return any(x in t for x in terms)
        def _filter_lines(txt, patterns=None, max_lines=80):
            if not txt:
                return "(no data)"
            lines = txt.splitlines()
            if not patterns:
                return "\n".join(lines[:max_lines])
            pats = [p.lower() for p in patterns]
            kept = []
            for ln in lines:
                lnl = ln.lower()
                if any(p in lnl for p in pats):
                    kept.append(ln)
                if len(kept) >= max_lines:
                    break
            return "\n".join(kept or lines[:max_lines])

        appendix = "\n\n## Appendix A: Relevant Artifacts\n"
        # Domain & DNS or mentions
        if (area.get("domain_dns", "Medium") != "Low") or _has_terms(obs_text, ["dns", "ns", "mx", "spf", "dkim", "dmarc", "dnssec"]):
            appendix += subsection("DNS (dig)", _filter_lines(dns_txt, max_lines=60))
            appendix += subsection("crt.sh", _filter_lines(crtsh_txt, max_lines=60))
        # Security Headers
        if (area.get("sec_headers", "Medium") != "Low") or _has_terms(obs_text, ["header", "hsts", "csp", "x-frame", "x-content-type", "referrer-policy", "permissions-policy"]):
            appendix += subsection("HTTP Headers", _filter_lines(headers_txt, patterns=[
                "strict-transport-security", "content-security-policy", "x-frame-options",
                "x-content-type-options", "referrer-policy", "permissions-policy", "x-xss-protection"
            ], max_lines=40))
        # SSL/TLS
        if (area.get("ssl", "Medium") != "Low") or _has_terms(obs_text, ["tls", "ssl", "certificate", "cipher", "weak", "legacy"]):
            appendix += subsection("SSL/TLS", _filter_lines(ssl_labs_txt, patterns=[
                "tls_version", "cipher", "subject_cn", "issuer_cn", "notbefore", "notafter"
            ], max_lines=40))
        # Tech Stack
        if (area.get("tech_stack", "Medium") != "Low") or _has_terms(obs_text, ["wordpress", "apache", "nginx", "iis", "jquery", "outdated", "version"]):
            appendix += subsection("WhatWeb", _filter_lines(whatweb_txt, max_lines=60))
        # Shodan (summary / excerpt / full) in relevant mode
        if _has_terms(obs_text, ["shodan", "open port", "exposed", "service"]) or (area.get("domain_dns", "Medium") != "Low") or (area.get("ssl", "Medium") != "Low"):
            _incl = (state.get("shodan_include") or "excerpt").lower()
            if _incl == "full":
                appendix += subsection("Shodan", shodan_txt)
            elif _incl == "summary":
                appendix += subsection("Shodan (summary)", _summarize_shodan_text(shodan_txt))
            else:
                appendix += subsection("Shodan (summary)", _summarize_shodan_text(shodan_txt))
                excerpt_lines =  int(state.get("shodan_excerpt_lines") or 25)
                appendix += subsection("Shodan (excerpt)", _filter_lines(shodan_txt, patterns=["port:", "cve", "http", "ssl", "ssh", "rdp", "ftp"], max_lines=excerpt_lines))
        # Subdomains
        if _has_terms(obs_text, ["subdomain", "staging", "dev", "admin"]) or (subdomains_txt.strip()):
            appendix += subsection("Subdomains (subfinder)", _filter_lines(subdomains_txt, max_lines=80))
        # WHOIS if DNS issues noted
        if _has_terms(obs_text, ["registrar", "privacy", "whois", "expiration", "expires", "name server"]):
            appendix += subsection("WHOIS", _filter_lines(whois_txt, max_lines=60))
        report += appendix

    # Always produce a separate comprehensive artifacts + run log file alongside the report
    try:
        full_txt = []
        def _add_block(title, body):
            full_txt.append(f"===== {title} =====\n")
            full_txt.append(((body or "").strip()) + "\n\n")
        _add_block("WHOIS", whois_txt)
        _add_block("DNS (dig)", dns_txt)
        _add_block("HTTP Headers", headers_txt)
        _add_block("robots.txt", robots_txt)
        _add_block("WhatWeb", whatweb_txt)
        _add_block("Subdomains (subfinder)", subdomains_txt)
        _add_block("crt.sh", crtsh_txt)
        _add_block("SSL/TLS", ssl_labs_txt)
        _add_block("Shodan", shodan_txt)
        logs_all = "\n".join(getattr(_log_memory_handler, "records", []))
        _add_block("Run Log", logs_all)
        full_out = "".join(full_txt)
        full_out = _sanitize_ascii(full_out)
        full_path = case_dir / "reports" / "report_full_logs.txt"
        full_path.write_text(full_out, encoding="utf-8")
        logger.debug("generate_report(): wrote full artifacts to %s", full_path)
    except Exception:
        logger.exception("Failed writing comprehensive artifacts file")

    # Sanitize for ASCII-only (avoids LaTeX/PDF unicode issues) and write to case directory
    report = _sanitize_ascii(report)
    # Write to case directory (existing behavior)
    md_path_case = case_dir / "reports" / "report.md"
    md_path_case.write_text(report)
    logger.debug("generate_report(): wrote markdown to %s", md_path_case)

    # Also write a copy into current working directory named after the case
    safe_client = _safe_slug(state.get("client", "case"))
    md_path_cwd = Path.cwd() / f"{safe_client}_report.md"
    md_path_cwd.write_text(report)
    logger.debug("generate_report(): wrote markdown to %s", md_path_cwd)

    # PDF (if pandoc present) - produce in both locations
    if shutil.which("pandoc") is None:
        logger.warning("pandoc not found; skipping PDF generation")
    else:
        pdf_case = case_dir / 'reports' / 'report.pdf'
        pdf_cwd = Path.cwd() / f"{safe_client}_report.pdf"
        for src, dst in ((md_path_case, pdf_case), (md_path_cwd, pdf_cwd)):
            logger.debug("generate_report(): invoking pandoc to produce %s", dst)
            result = subprocess.run(
                f"pandoc \"{src}\" -o \"{dst}\"",
                shell=True
            )
            logger.debug("pandoc return code: %s", getattr(result, "returncode", None))

    state["checklist"]["report_generated"] = True

# =========================
# MAIN
# =========================

def main():
    logger.debug("Entering main()")
    # CLI options
    try:
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--artifact-mode", choices=["none", "relevant", "full"], dest="artifact_mode")
        parser.add_argument("--shodan-include", choices=["summary", "excerpt", "full"], dest="shodan_include")
        parser.add_argument("--shodan-excerpt-lines", type=int, dest="shodan_excerpt_lines")
        parser.add_argument("--batch", action="store_true", dest="batch", help="Run Google Sheets batch processing and exit")
        parser.add_argument("--help-all", action="store_true", dest="help_all", help="Show extended help and exit")
        parser.add_argument("-h", "--help", action="help", help="show this help message and exit")
        args, _unknown = parser.parse_known_args()
    except Exception:
        args = type("Args", (), {"artifact_mode": None, "batch": False, "help_all": False})()
    # Extended help early exit
    try:
        _env_help_all = str(os.getenv("SECOPS_HELP_ALL", "")).strip().lower() in {"1", "true", "yes"}
        if getattr(args, "help_all", False) or _env_help_all:
            _print_help_extended()
            return
    except Exception:
        logger.exception("Extended help printing failed; continuing")
    # If Google not configured yet, trigger setup to ensure user sees OAuth prompts
    try:
        if _gbuild is not None and not _google_config_ready():
            logger.debug("Google integrations not configured; will prompt for setup")
    except Exception:
        logger.exception("Auto Google setup check failed; continuing")
    # Offer to configure Google integrations up front so users see the OAuth/setup prompts
    try:
        if _gbuild is not None and not _google_config_ready():
            if yes_no("Configure Google integrations (Drive/Docs/Sheets) now?"):
                setup_google_integration_interactive()
    except Exception:
        logger.exception("Google setup prompt failed; continuing")
    # Auto-batch via CLI flag or env var SECOPS_BATCH
    try:
        _env_batch = str(os.getenv("SECOPS_BATCH", "")).strip().lower() in {"1", "true", "yes"}
        # If batch was explicitly requested but Google libs are missing, do not fall back to single-case
        if (args.batch or _env_batch) and (_gbuild is None):
            print("[!] Google API libraries are not installed in this environment. Install: pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib")
            print("[!] Batch mode cannot run without Google libraries. Exiting.")
            return
        # Batch is interactive by default unless SECOPS_NON_INTERACTIVE or SECOPS_AUTO are set
        _env_non_interactive = str(os.getenv("SECOPS_NON_INTERACTIVE", "")).strip().lower() in {"1", "true", "yes"}
        _env_auto = str(os.getenv("SECOPS_AUTO", "")).strip().lower() in {"1", "true", "yes"}
        _interactive_batch = not (_env_non_interactive or _env_auto)
        if _gbuild is not None and (args.batch or _env_batch or _should_auto_batch()):
            process_batch_from_google_sheet(interactive=_interactive_batch)
            print("[+] Batch processing complete")
            return
    except Exception:
        logger.exception("Auto batch execution failed; continuing")
    try:
        if _gbuild is not None and yes_no("Process all pending sites from Google Sheet now?"):
            process_batch_from_google_sheet()
            print("[+] Batch processing complete")
            return
    except Exception:
        logger.exception("Batch mode prompt failed; continuing with single-case flow")
    # Ensure one-time setup for prepared_by and default contact in single-case flow
    try:
        _ = _get_prepared_by(interactive=True)
        _ = _get_default_contact(interactive=True)
    except Exception:
        logger.exception("One-time prepared_by/default_contact setup failed; continuing")
    case_dir, state = init_case()
    try:
        cfg0 = _load_config()
        state["artifact_mode"] = (args.artifact_mode or cfg0.get("artifact_mode") or "relevant")
        state["shodan_include"] = (args.shodan_include or cfg0.get("shodan_include") or "excerpt")
        if getattr(args, "shodan_excerpt_lines", None):
            try:
                state["shodan_excerpt_lines"] = max(5, min(500, int(args.shodan_excerpt_lines)))
            except Exception:
                pass
    except Exception:
        state["artifact_mode"] = "relevant"
        state["shodan_include"] = "excerpt"

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
    # Step: SSL/TLS
    if os.getenv("SECOPS_AUTO") or os.getenv("SECOPS_NON_INTERACTIVE"):
        logger.debug("main(): ssl_tls_probe() start")
        ssl_tls_probe(case_dir, state)
        logger.debug("main(): ssl_tls_probe() complete")
    else:
        logger.debug("main(): manual_ssl() start")
        manual_ssl(case_dir, state)
        logger.debug("main(): manual_ssl() complete")
    # Step: Shodan
    logger.debug("main(): shodan_lookup() start")
    shodan_lookup(case_dir, state)
    logger.debug("main(): shodan_lookup() complete")
    # Step: Upload screenshots
    logger.debug("main(): upload_screenshots() start")
    upload_screenshots(case_dir, state)
    logger.debug("main(): upload_screenshots() complete")

    # Step: AI assistance (uses recon + manual notes to prefill fields)
    logger.debug("main(): ai_assist() start")
    ai_assist(case_dir, state)
    logger.debug("main(): ai_assist() complete")

    # Step: Collect report inputs (prepared_by, contact, area ratings, observations)
    logger.debug("main(): report_inputs() start")
    report_inputs(case_dir, state)
    logger.debug("main(): report_inputs() complete")

    # === Risk & Report ===
    logger.debug("main(): risk_scoring() start")
    risk_scoring(case_dir, state)
    logger.debug("main(): risk_scoring() complete")
    logger.debug("main(): generate_report() start")
    generate_report(case_dir, state)
    logger.debug("main(): generate_report() complete")
    try:
        if yes_no("Send initial outreach email with the report now?"):
            suggested = _get_contact_for(state.get("domain")) or state.get("contact") or _get_default_contact(interactive=False)
            rec = prompt(f"Recipient email (default {suggested})") or suggested
            rec = (rec or "").strip()
            if rec:
                _remember_contact(state.get("domain"), rec)
                ok = send_outreach_post_report(case_dir, state, rec, recipient_name=state.get("business_name"))
                print("[+] Email sent" if ok else "[!] Email failed")
    except Exception:
        logger.exception("Interactive outreach email failed")
    try:
        if yes_no("Process any due follow-ups now?"):
            n = process_due_followups()
            print(f"[+] Follow-ups sent: {n}")
    except Exception:
        logger.exception("Follow-up processing failed")

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
