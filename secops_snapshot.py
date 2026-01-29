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
from urllib.parse import urlparse
import getpass
import socket
import ssl
try:
    from openai import OpenAI as _OpenAIClient  # New-style client
except Exception:  # pragma: no cover
    _OpenAIClient = None
try:
    import openai as _openai_mod  # Legacy client
except Exception:  # pragma: no cover
    _openai_mod = None

import logging

# Logging configuration
logging.basicConfig(
    level=logging.DEBUG,
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

# =========================
# CONFIGURATION
# =========================

BASE_DIR = Path.home() / "secops"
CLIENTS_DIR = BASE_DIR / "clients"
CONFIG_FILE = BASE_DIR / "config.json"

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

def _load_config() -> dict:
    try:
        if CONFIG_FILE.exists():
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        pass
    return {}

def _save_config(cfg: dict) -> None:
    try:
        CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = json.dumps(cfg or {}, indent=2)
        CONFIG_FILE.write_text(tmp, encoding="utf-8")
    except Exception:
        logger.exception("Failed to save config at %s", CONFIG_FILE)

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
    key = getpass.getpass("[+] Enter OpenAI API key (starts with 'sk-'): ").strip()
    if key:
        cfg["openai_api_key"] = key
        _save_config(cfg)
    return key

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
    key = getpass.getpass("[+] Enter Shodan API key: ").strip()
    if key:
        cfg["shodan_api_key"] = key
        _save_config(cfg)
    return key

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
    api_key = _get_openai_api_key(interactive=True)
    if not api_key:
        logger.warning("No OpenAI API key provided; skipping AI assistance")
        return

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

    sys_prompt = (
        "You are a security analyst. Read passive recon artifacts and suggest: "
        "area risk levels (use labels Low/Medium/High, not abbreviations) for Domain/DNS, Tech Stack, Email/Creds, SSL, Sec Headers; "
        "a Key Observations section in the business template style (3–5 items); and an overall exposure score 0–100. "
        "Then compose a complete, clean Markdown report body that includes: a title in the format '<Business Name> Passive Security Exposure Snapshot', "
        "a header block with Prepared for, Website, Date, Prepared by; and sections 1–7 (Executive Summary, Exposure Overview, Key Observations, "
        "Exposure Risk Score, Recommended Next Steps, Authorization & Disclosure, Optional Consultation). "
        "Render the Exposure Overview as a 3-column markdown table with headers 'Area', 'Status', 'Risk Level' and values 'Observed' for Status. "
        "In the Executive Summary include both 'Overall Exposure Rating' and 'Overall Exposure Score: N / 100'. "
        "Map score to rating using: 0–24 Low, 25–49 Moderate, 50–74 Elevated, 75–100 High. "
        "In section 7 include the provided contact as 'Contact: <contact>'. "
        "Do NOT include any appendices; the system will add artifacts and run log later. "
        "Output ONLY JSON with keys: area_ratings (object with keys: domain_dns, tech_stack, email_creds, ssl, sec_headers), "
        "observations_md (string), suggested_score (int), report_md (string with the full Markdown report)."
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
    prepared_by = state.get("prepared_by", "Your Business Name")
    contact = state.get("contact", "you@company.com")
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
    try:
        # Ensure Shodan CLI is initialized; prompt to init if needed
        try:
            info = subprocess.run(["shodan", "info"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        except Exception:
            info = None
        if (not info) or info.returncode != 0:
            try:
                if yes_no("Shodan CLI appears uninitialized. Initialize now?"):
                    key = _get_shodan_api_key(interactive=True)
                    if key:
                        subprocess.run(["shodan", "init", key], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            except Exception:
                pass
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
            ips = set()
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

    # Recon sections and manual notes
    def section(title, body):
        body = body.strip()
        if not body:
            body = "(no data)"
        return f"\n\n## {title}\n\n```\n{body}\n```\n"

    # Append appendices for artifacts and logs
    def subsection(title, body):
        body = body.strip() or "(no data)"
        return f"\n\n### {title}\n\n```\n{body}\n```\n"

    appendix = ""
    appendix += "\n\n## Appendix A: Recon Artifacts\n"
    appendix += subsection("WHOIS", whois_txt)
    appendix += subsection("DNS (dig)", dns_txt)
    appendix += subsection("HTTP Headers", headers_txt)
    appendix += subsection("robots.txt", robots_txt)
    appendix += subsection("WhatWeb", whatweb_txt)
    appendix += subsection("Subdomains (subfinder)", subdomains_txt)
    appendix += subsection("crt.sh", crtsh_txt)
    appendix += subsection("SSL/TLS", ssl_labs_txt)
    appendix += subsection("Shodan", shodan_txt)

    logs = "\n".join(getattr(_log_memory_handler, "records", []))
    appendix += "\n\n## Appendix B: Run Log\n"
    appendix += subsection("Run Log", logs)

    report += appendix

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
