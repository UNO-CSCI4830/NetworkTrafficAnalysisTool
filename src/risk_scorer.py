"""
risk_scorer.py
Scores each connection 0-100 based on how suspicious it looks.
heuristics based for now. Process name, port flags, path verification, and port mismatches.

Score ranges:
  0-24   LOW
  25-49  MEDIUM
  50-74  HIGH
  75-100 CRITICAL

Relates to issues: FR15 (Connection Risk Scoring), NR8 (Malicious Traffic Alert), FR11 (Attack Vector Recognition)
"""

from pathlib import Path

# processes that shouldn't really be making internet connections
# these are called "LOLBins" living off the land binaries, commonly abused by malware
SUSPICIOUS_PROCESSES = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "msiexec.exe", "wmic.exe", "schtasks.exe",
}

# windows system processes that malware likes to impersonate
SPOOFABLE_PROCESSES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "explorer.exe",
    "taskhost.exe", "taskhostw.exe", "conhost.exe",
}

# where real windows system processes should live
TRUSTED_PATHS = (
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows" + "\\",
    r"c:\program files" + "\\",
    r"c:\program files (x86)" + "\\",
)


def _is_trusted_path(path):
    # guard against None, empty string, or "unknown"
    if not path or path == "unknown":
        return False
    p = path.lower().replace("/", "\\")
    return any(p.startswith(t) for t in TRUSTED_PATHS)


def score_risk(conn):
    """
    Takes an enriched connection dict (output of enrich() + enrich_dns()) and
    returns a risk assessment dict with:
        score   - int 0-100
        label   - LOW / MEDIUM / HIGH / CRITICAL
        reasons - list of strings explaining why

    Fields we read from conn (all set by collector.py and enrichment.py):
        process_name    - e.g. "svchost.exe"
        process_path    - e.g. "C:\\Windows\\System32\\svchost.exe" or "unknown"
        process_known   - True if process is in known_processes.json
        remote_ip       - e.g. "142.250.80.46" or "" if no remote connection
        remote_port     - e.g. 443 or None
        port_suspicious - True if port is flagged in known_ports.json
        port_mismatch   - True if process is using a port outside its expected_ports list
        service_name    - e.g. "HTTPS" from known_ports.json
    """
    score = 0
    reasons = []

    process  = (conn.get("process_name") or "unknown").lower()
    path     = conn.get("process_path") or ""
    ip       = conn.get("remote_ip") or ""
    port     = conn.get("remote_port")

    # these come from enrich() in enrichment.py
    port_suspicious = conn.get("port_suspicious", False)
    port_mismatch   = conn.get("port_mismatch", False)
    process_known   = conn.get("process_known", True)

    # loopback is always fine
    if ip.startswith("127.") or ip == "::1":
        return {"score": 0, "label": "LOW", "reasons": ["Loopback connection, local traffic only."]}

    # heuristic checks 

    # not in our known processes whitelist
    if not process_known:
        score += 20
        reasons.append(f"'{conn.get('process_name')}' is not a recognized Windows process.")

    # LOLBin / scripting engine making outbound connection
    # match on exact basename to avoid false positives on names like "my_powershell_wrapper.exe"
    process_basename = Path(process).name
    if process_basename in SUSPICIOUS_PROCESSES:
        score += 30
        reasons.append(f"'{process_basename}' is commonly abused by malware for command execution (LOLBin).")

    # looks like a system process but running from the wrong folder
    if process_basename in SPOOFABLE_PROCESSES and not _is_trusted_path(path):
        score += 35
        reasons.append(
            f"'{conn.get('process_name')}' looks like a system process but is running from "
            f"'{path}' instead of System32. Possible masquerading."
        )

    # enrich() checks if the process is on a port outside its expected_ports list
    if port_mismatch:
        score += 20
        reasons.append(
            f"'{conn.get('process_name')}' is using port {port} which isn't in its expected port list."
        )

    # port is flagged in known_ports.json
    if port_suspicious:
        score += 25
        reasons.append(f"Port {port} ({conn.get('service_name', 'unknown')}) is flagged as suspicious.")

    # can't verify where the process is running from
    if not path or path == "unknown":
        score += 10
        reasons.append("Could not verify the process executable path.")

    # clamp to 100 and assign label
    score = min(score, 100)

    if score >= 75:
        label = "CRITICAL"
    elif score >= 50:
        label = "HIGH"
    elif score >= 25:
        label = "MEDIUM"
    else:
        label = "LOW"

    if not reasons:
        reasons.append("No suspicious indicators found.")

    return {"score": score, "label": label, "reasons": reasons}
