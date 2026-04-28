"""
advanced_scanner.py — Docker-based vulnerability tools for PRAWL
Integrates: Nmap, Nikto, SQLMap
Each tool runs as an ephemeral Docker container via subprocess.
"""

import subprocess
import json
import re
import xml.etree.ElementTree as ET
import requests
from typing import Dict, Any, Tuple


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def _run_docker(cmd: list, timeout: int = 120) -> Tuple[str, str, int]:
    """
    Run any docker command. Returns (stdout, stderr, returncode).
    returncode -2  → Docker not found / not running
    returncode -1  → Timed out
    """
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return proc.stdout, proc.stderr, proc.returncode

    except subprocess.TimeoutExpired:
        return "", "⏱️ Scan timed out — target may be unreachable.", -1

    except FileNotFoundError:
        return (
            "",
            "🐋 Docker not found. Please install Docker Desktop and make sure it is running.",
            -2,
        )

    except Exception as exc:
        return "", f"Unexpected error: {exc}", -3


def _extract_hostname(url: str) -> str:
    """Strip protocol / path and return bare hostname."""
    url = url.strip()
    for prefix in ("https://", "http://", "www."):
        if url.lower().startswith(prefix):
            url = url[len(prefix):]
            break # Avoid multiple stripping
    return url.split("/")[0].split("?")[0].split("#")[0]


def _ensure_protocol(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


# ──────────────────────────────────────────────
# DOCKER AVAILABILITY CHECK
# ──────────────────────────────────────────────

def check_docker_available() -> Dict[str, Any]:
    """
    Quick health-check. Call this before running scans so the
    frontend can warn the user if Docker is not running.
    """
    out, err, code = _run_docker(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=10)
    if code == 0 and out.strip():
        return {"available": True, "version": out.strip()}
        
    error_msg = err.strip() or "Docker daemon not responding. Is Docker Desktop running?"
    if "permission denied" in error_msg.lower():
        error_msg = "Docker permission denied. Add user to docker group (sudo usermod -aG docker $USER) or run as root."
        
    return {
        "available": False,
        "error": error_msg,
    }


# ──────────────────────────────────────────────
# NMAP
# ──────────────────────────────────────────────

# Ports that are almost always dangerous when exposed to the internet
_DANGEROUS_PORTS = {
    21:    ("FTP",           "Unencrypted file transfer — credentials sent in plain text", "high"),
    22:    ("SSH",           "Remote shell access exposed — ensure key-only auth is enforced", "medium"),
    23:    ("Telnet",        "CRITICAL: fully unencrypted remote access, deprecated protocol", "critical"),
    25:    ("SMTP",          "Mail relay may be open to spam / spoofing abuse", "medium"),
    53:    ("DNS",           "DNS service exposed — check for zone-transfer vulnerability", "medium"),
    3306:  ("MySQL",         "Database port exposed to internet — high risk of data breach", "critical"),
    3389:  ("RDP",           "Windows Remote Desktop exposed — common ransomware entry point", "critical"),
    5432:  ("PostgreSQL",    "Database port exposed to internet", "critical"),
    5900:  ("VNC",           "Remote desktop (VNC) exposed — often unauthenticated", "critical"),
    6379:  ("Redis",         "Redis cache exposed — usually has no authentication by default", "critical"),
    8080:  ("HTTP-alt",      "Alternative HTTP port — may expose dev/admin interfaces", "medium"),
    8443:  ("HTTPS-alt",     "Alternative HTTPS port — verify it is intentionally public", "low"),
    9200:  ("Elasticsearch", "Elasticsearch exposed — often unauthenticated, data leak risk", "critical"),
    27017: ("MongoDB",       "MongoDB exposed — frequently found unauthenticated in the wild", "critical"),
}

_NMAP_PORTS = ",".join(str(p) for p in _DANGEROUS_PORTS)


def run_nmap_scan(target: str) -> Dict[str, Any]:
    """
    Run Nmap inside Docker.  Uses the official instrumentisto/nmap image.
    Returns a structured dict with open ports, service versions, and risk findings.
    """
    hostname = _extract_hostname(target)

    cmd = [
        "docker", "run", "--rm",
        "--network=host",
        "instrumentisto/nmap",
        "-sV",                        # service/version detection
        "--version-intensity", "3",   # balanced speed vs accuracy
        "-p", _NMAP_PORTS,
        "--script", "banner,ssl-cert,http-title",
        "--open",                     # only show open ports
        "-oX", "-",                   # XML to stdout
        "--host-timeout", "60s",
        hostname,
    ]

    stdout, stderr, code = _run_docker(cmd, timeout=90)

    if code == -2:
        return _nmap_error("Docker not installed or not running.")
    if code == -1:
        return _nmap_error("Nmap scan timed out (60 s). Target may be unreachable.")
    if not stdout.strip():
        return _nmap_error(f"No output from Nmap. {stderr[:200]}")

    return _parse_nmap_xml(stdout, hostname)


def _nmap_error(msg: str) -> Dict[str, Any]:
    return {"error": msg, "hostname": "", "ports": [], "risk_findings": [], "scan_tool": "nmap"}


def _parse_nmap_xml(xml_output: str, hostname: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "scan_tool": "nmap",
        "hostname":   hostname,
        "ports":      [],
        "risk_findings": [],
        "scripts":    [],
    }

    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        result["error"] = f"Could not parse Nmap XML: {exc}"
        return result

    for host in root.findall("host"):
        for port_elem in host.findall(".//port"):
            port_id   = int(port_elem.get("portid", 0))
            state_el  = port_elem.find("state")
            svc_el    = port_elem.find("service")

            if state_el is None or state_el.get("state") != "open":
                continue

            svc_name    = svc_el.get("name",    "unknown") if svc_el is not None else "unknown"
            svc_version = svc_el.get("version", "")        if svc_el is not None else ""
            svc_product = svc_el.get("product", "")        if svc_el is not None else ""

            port_record = {
                "port":    port_id,
                "service": svc_name,
                "product": svc_product,
                "version": svc_version,
                "state":   "open",
            }
            result["ports"].append(port_record)

            # Collect script output (banners, titles, certs)
            for script in port_elem.findall("script"):
                result["scripts"].append({
                    "port":   port_id,
                    "script": script.get("id"),
                    "output": script.get("output", "")[:300],
                })

            # Flag dangerous open ports
            if port_id in _DANGEROUS_PORTS:
                name, desc, severity = _DANGEROUS_PORTS[port_id]
                result["risk_findings"].append({
                    "port":        port_id,
                    "service":     name,
                    "description": desc,
                    "severity":    severity,
                    "version":     f"{svc_product} {svc_version}".strip(),
                })

    return result


# ──────────────────────────────────────────────
# NIKTO
# ──────────────────────────────────────────────

def run_nikto_scan(target: str) -> Dict[str, Any]:
    """
    Run Nikto web vulnerability scanner inside Docker.
    Uses the frapsoft/nikto image.
    """
    target = _ensure_protocol(target)

    cmd = [
        "docker", "run", "--rm",
        "--network=host",
        "frapsoft/nikto",
        "-h",            target,
        "-maxtime",      "90s",
        "-ask",          "no",    # prevents interactive prompts that could hang the scanner
        "-Format",       "txt",   # plain text is most reliable across versions
    ]

    stdout, stderr, code = _run_docker(cmd, timeout=120)

    if code == -2:
        return _nikto_error("Docker not installed or not running.")
    if code == -1:
        return _nikto_error("Nikto scan timed out (90 s).")

    combined = stdout + "\n" + stderr
    return _parse_nikto_text(combined, target)


def _nikto_error(msg: str) -> Dict[str, Any]:
    return {"error": msg, "target": "", "vulnerabilities": [], "findings_count": 0, "scan_tool": "nikto"}


# Severity keywords to auto-classify findings
_NIKTO_CRITICAL_KW = ["cve-", "osvdb", "xss", "sql injection", "remote code", "rce", "directory traversal"]
_NIKTO_HIGH_KW     = ["vulnerable", "unsafe", "outdated", "dangerous", "exposed admin"]
_NIKTO_MEDIUM_KW   = ["allowed method", "missing header", "clickjack", "disclosure", "information"]


def _classify_nikto(text: str) -> str:
    t = text.lower()
    if any(k in t for k in _NIKTO_CRITICAL_KW):
        return "critical"
    if any(k in t for k in _NIKTO_HIGH_KW):
        return "high"
    if any(k in t for k in _NIKTO_MEDIUM_KW):
        return "medium"
    return "info"


def _parse_nikto_text(output: str, target: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "scan_tool":      "nikto",
        "target":         target,
        "server_banner":  None,
        "vulnerabilities": [],
        "findings_count": 0,
    }

    for line in output.splitlines():
        line = line.strip()

        # Server banner
        if line.lower().startswith("+ server:"):
            result["server_banner"] = line[9:].strip()

        # Findings start with "+ "
        elif line.startswith("+ ") and len(line) > 4:
            text = line[2:].strip()

            # Skip pure informational lines (start time, target IP, etc.) and Nikto warnings
            if any(skip in text.lower() for skip in [
                "target ip:", "target hostname:", "target port:", "start time:", "end time:", 
                "1 host(s) tested", "error: host maximum execution time", "error: unable to open"
            ]):
                continue

            result["vulnerabilities"].append({
                "description": text,
                "severity":    _classify_nikto(text),
                "reference":   _extract_cve(text),
            })

    result["findings_count"] = len(result["vulnerabilities"])

    # Sort: critical → high → medium → info
    _order = {"critical": 0, "high": 1, "medium": 2, "info": 3}
    result["vulnerabilities"].sort(key=lambda v: _order.get(v["severity"], 4))

    return result


def _extract_cve(text: str) -> str | None:
    """Pull CVE/OSVDB reference from a finding line."""
    m = re.search(r"(CVE-\d{4}-\d+|OSVDB-\d+)", text, re.IGNORECASE)
    return m.group(0).upper() if m else None


# ──────────────────────────────────────────────
# SQLMAP
# ──────────────────────────────────────────────

def run_sqlmap_scan(target: str, test_forms: bool = True) -> Dict[str, Any]:
    """
    Run SQLMap inside Docker.  Uses the paoloo/sqlmap image.

    ⚠️  ONLY call this with explicit user consent — the endpoint
        /api/advanced-scan enforces a consent checkbox.

    test_forms=True  →  also crawl and test HTML forms (slower but thorough)
    """
    target = _ensure_protocol(target)

    cmd = [
        "docker", "run", "--rm",
        "--network=host",
        "secsi/sqlmap",
        "-u",           target,
        "--batch",                  # never prompt for input
        "--level=1",                # lowest test depth
        "--risk=1",                 # safest payloads only
        "--timeout=20",
        "--retries=1",
        "--threads=2",
        "--technique=BEU",          # Boolean / Error / Union only — no time-based (slow)
        "--output-dir=/tmp/sqlmap-out",
    ]

    if test_forms:
        cmd.append("--forms")       # discover and test HTML form inputs

    stdout, stderr, code = _run_docker(cmd, timeout=150)

    if code == -2:
        return _sqlmap_error("Docker not installed or not running.")
    if code == -1:
        return _sqlmap_error("SQLMap scan timed out (150 s).")

    combined = stdout + "\n" + stderr
    return _parse_sqlmap_output(combined, target)


def _sqlmap_error(msg: str) -> Dict[str, Any]:
    return {"error": msg, "target": "", "injectable": False, "injections": [], "scan_tool": "sqlmap"}


def _parse_sqlmap_output(output: str, target: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "scan_tool":   "sqlmap",
        "target":       target,
        "injectable":   False,
        "dbms":         None,
        "injections":   [],
        "parameters":   [],
        "summary":      "",
        "raw_snippet":  "",
    }

    lower = output.lower()
    result["injectable"] = (
        "is vulnerable" in lower
        or "appears to be injectable" in lower
        or "injectable" in lower
        and "not injectable" not in lower
    )

    # DBMS detection
    dbms_m = re.search(r"back-end DBMS[:\s]+(.+)", output, re.IGNORECASE)
    if dbms_m:
        result["dbms"] = dbms_m.group(1).strip()

    # Parameter names
    param_matches = re.findall(r"Parameter[:\s]+['\"]?([A-Za-z0-9_\-]+)['\"]?", output, re.IGNORECASE)
    result["parameters"] = list(set(param_matches))

    # Injection techniques found
    type_matches = re.findall(r"Type:\s*(.+)", output, re.IGNORECASE)
    payload_matches = re.findall(r"Title:\s*(.+)", output, re.IGNORECASE)
    result["injections"] = [t.strip() for t in type_matches + payload_matches][:10]

    # Friendly summary
    if result["injectable"]:
        dbms_str = f" ({result['dbms']})" if result["dbms"] else ""
        result["summary"] = (
            f"🚨 SQL Injection FOUND{dbms_str} — attacker could read/modify your database. "
            f"Fix immediately by using parameterised queries."
        )
    elif "no injectable" in lower or "not injectable" in lower:
        result["summary"] = "✅ No SQL injection vulnerabilities detected on tested parameters."
    else:
        result["summary"] = "ℹ️ Scan completed. Review injections list for details."

    # Keep a short raw snippet for the AI to analyse
    lines = [l for l in output.splitlines() if l.strip() and not l.startswith("  ")]
    result["raw_snippet"] = "\n".join(lines[:40])

    return result


# ──────────────────────────────────────────────
# WHATWEB (Technology Fingerprinting)
# ──────────────────────────────────────────────

def run_whatweb_scan(target: str) -> Dict[str, Any]:
    """
    Run WhatWeb inside Docker to fingerprint the technology stack.
    Uses the secsi/whatweb image.
    """
    target = _ensure_protocol(target)

    cmd = [
        "docker", "run", "--rm",
        "--network=host",
        "secsi/whatweb",
        "-a", "3", "--log-json", "-", "--quiet",
        target
    ]

    stdout, stderr, code = _run_docker(cmd, timeout=90)

    if code == -2:
        return _whatweb_error("Docker not installed or not running.")
    if code == -1:
        return _whatweb_error("WhatWeb scan timed out (90 s).")

    return _parse_whatweb_json(stdout, target)

def _whatweb_error(msg: str) -> Dict[str, Any]:
    return {"error": msg, "target": "", "plugins": [], "scan_tool": "whatweb"}

def _parse_whatweb_json(output: str, target: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "scan_tool": "whatweb",
        "target": target,
        "plugins": [],
    }

    try:
        start = output.find("[")
        if start != -1:
            clean_out = output[start:]
            data = json.loads(clean_out)
            if isinstance(data, list) and len(data) > 0:
                plugins = data[0].get("plugins", {})
                for name, details in plugins.items():
                    if name.lower() in ["country", "ip"]:
                        continue
                    version = details.get("version", [""])[0] if "version" in details else ""
                    string = details.get("string", [""])[0] if "string" in details else ""
                    result["plugins"].append({
                        "name": str(name),
                        "version": str(version),
                        "string": str(string)
                    })
    except json.JSONDecodeError:
        result["error"] = "Failed to parse WhatWeb JSON output."
    
    return result


# ──────────────────────────────────────────────
# COMBINED ADVANCED SCAN (all three tools)
# ──────────────────────────────────────────────

import concurrent.futures

def run_full_advanced_scan(target: str, consent: bool = False) -> Dict[str, Any]:
    """
    Orchestrates Nmap + Nikto + SQLMap.
    SQLMap is skipped unless consent=True.
    Returns a unified dict for the API response.
    """
    docker_status = check_docker_available()
    if not docker_status["available"]:
        return {
            "error":   docker_status["error"],
            "nmap":    None,
            "nikto":   None,
            "sqlmap":  None,
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        f_nmap = executor.submit(run_nmap_scan, target)
        f_nikto = executor.submit(run_nikto_scan, target)
        f_sqlmap = executor.submit(run_sqlmap_scan, target) if consent else None
        f_crt = executor.submit(run_subdomain_scan, target)
        f_whatweb = executor.submit(run_whatweb_scan, target)

        nmap_result = f_nmap.result()
        nikto_result = f_nikto.result()
        sqlmap_result = f_sqlmap.result() if f_sqlmap else {"scan_tool": "sqlmap", "skipped": True, "reason": "User consent not given"}
        crt_result = f_crt.result()
        whatweb_result = f_whatweb.result()

    return {
        "target":  target,
        "nmap":    nmap_result,
        "nikto":   nikto_result,
        "sqlmap":  sqlmap_result,
        "whatweb": whatweb_result,
        "crt_sh":  crt_result,
    }


# ──────────────────────────────────────────────
# OSINT: SUBDOMAIN ENUMERATION (crt.sh)
# ──────────────────────────────────────────────

def run_subdomain_scan(target: str) -> Dict[str, Any]:
    """
    Query crt.sh (Certificate Transparency logs) for subdomains of the target.
    This is extremely fast and completely stealthy (OSINT).
    """
    hostname = _extract_hostname(target)
    # Strip any 'www.' to get the base domain for wider search
    if hostname.startswith('www.'):
        hostname = hostname[4:]
        
    result = {
        "scan_tool": "crt_sh",
        "target": target,
        "base_domain": hostname,
        "subdomains": [],
        "count": 0,
        "error": None
    }
    
    try:
        # User-Agent is required because crt.sh blocks default Python requests UA
        headers = {'User-Agent': 'PRAWL-Scanner/1.0'}
        url = f"https://crt.sh/?q=%.{hostname}&output=json"
        
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            domain_set = set()
            for entry in data:
                # Some entries have multiple domains separated by newlines
                names = entry.get('name_value', '').split('\\n')
                for n in names:
                    n = n.strip().lower()
                    if n and not n.startswith('*'):  # exclude wildcards
                        domain_set.add(n)
            
            result["subdomains"] = sorted(list(domain_set))
            result["count"] = len(result["subdomains"])
        else:
            result["error"] = f"crt.sh returned status {resp.status_code}"
    except Exception as e:
        result["error"] = f"OSINT scan failed: {str(e)}"
        
    return result
