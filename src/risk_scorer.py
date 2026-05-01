"""
risk_scorer.py
Scores each connection 0-100 based on how suspicious it looks.
heuristics based for now. Process name, port flags, path verification, and port mismatches.

Score ranges (configurable in data/risk_scoring_config.json):
  0-24   LOW
  25-49  MEDIUM
  50-74  HIGH
  75-100 CRITICAL

Relates to issues: FR15, NR8, FR11, FR21, FR22
"""

import json
from pathlib import Path
from datetime import datetime

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

# (FR22) scoring weights and thresholds live in a config file so admins can tune them
CONFIG_PATH = Path("data/risk_scoring_config.json")
CONFIG_LOG_PATH = Path("data/risk_scoring_config.log")

# fallback if the config file is missing or broken, matches the original hardcoded values
DEFAULT_CONFIG = {
    "weights": {
        "unknown_process":  20,
        "lolbin":           30,
        "masquerading":     35,
        "port_mismatch":    20,
        "port_suspicious":  25,
        "unknown_path":     10,
    },
    "thresholds": {
        "low_max":     24,
        "medium_max":  49,
        "high_max":    74,
    },
}

# (FR11) MITRE ATT&CK technique mappings, https://attack.mitre.org
# maps specific lolbin process names to their associated technique IDs
LOLBIN_MITRE_MAP = {
    "powershell.exe": [("T1059.001", "PowerShell")],
    "cmd.exe":        [("T1059.003", "Windows Command Shell")],
    "wscript.exe":    [("T1059.005", "Visual Basic")],
    "cscript.exe":    [("T1059.005", "Visual Basic")],
    "mshta.exe":      [("T1218.005", "Mshta")],
    "rundll32.exe":   [("T1218.011", "Rundll32")],
    "regsvr32.exe":   [("T1218.010", "Regsvr32")],
    "certutil.exe":   [("T1140", "Deobfuscate/Decode Files"), ("T1105", "Ingress Tool Transfer")],
    "bitsadmin.exe":  [("T1197", "BITS Jobs")],
    "msiexec.exe":    [("T1218.007", "Msiexec")],
    "wmic.exe":       [("T1047", "Windows Management Instrumentation")],
    "schtasks.exe":   [("T1053.005", "Scheduled Task")],
}


def _is_trusted_path(path):
    # guard against None, empty string, or "unknown"
    if not path or path == "unknown":
        return False
    p = path.lower().replace("/", "\\")
    return any(p.startswith(t) for t in TRUSTED_PATHS)


def load_config():
    # (FR22) load weights/thresholds from disk, fall back to defaults if anything's wrong
    try:
        with open(CONFIG_PATH, "r") as f:
            cfg = json.load(f)
        if "weights" not in cfg or "thresholds" not in cfg:
            return DEFAULT_CONFIG
        return cfg
    except (FileNotFoundError, json.JSONDecodeError):
        return DEFAULT_CONFIG


def update_config(new_config, user_role, user_name):
    # (FR21 + FR22) admins can update the config, standard users get rejected.
    # every change gets logged with timestamp and username
    if user_role != "admin":
        return False

    with open(CONFIG_PATH, "w") as f:
        json.dump(new_config, f, indent=2)

    timestamp = datetime.now().isoformat()
    with open(CONFIG_LOG_PATH, "a") as f:
        f.write(f"[{timestamp}] user={user_name} role={user_role} updated config: {json.dumps(new_config)}\n")

    return True


def _classify_attack_vectors(fired):
    # (FR11) translate which heuristics fired into named attack vectors
    # so analysts get a quick read on what kind of threat this looks like
    vectors = []
    if "masquerading" in fired:
        vectors.append("Process Masquerading")
    if "lolbin" in fired:
        vectors.append("LOLBin Execution")
    if "port_suspicious" in fired:
        vectors.append("Suspicious Port Activity")
    if "port_mismatch" in fired:
        vectors.append("Anomalous Port Usage")
    if "unknown_process" in fired and "unknown_path" in fired:
        vectors.append("Unverified Binary")
    return vectors


def _map_mitre_techniques(fired, process_basename):
    # (FR11) takes which heuristics fired and returns matching MITRE ATT&CK technique IDs.
    # gives an industry standard reference instead of just our internal labels
    techniques = []
    seen = set()

    if "lolbin" in fired:
        for tid, name in LOLBIN_MITRE_MAP.get(process_basename, []):
            if tid not in seen:
                techniques.append({"id": tid, "name": name})
                seen.add(tid)

    if "masquerading" in fired and "T1036.005" not in seen:
        techniques.append({"id": "T1036.005", "name": "Masquerading: Match Legitimate Name or Location"})
        seen.add("T1036.005")

    if ("port_suspicious" in fired or "port_mismatch" in fired) and "T1571" not in seen:
        techniques.append({"id": "T1571", "name": "Non-Standard Port"})
        seen.add("T1571")

    if "unknown_process" in fired and "unknown_path" in fired and "T1027" not in seen:
        techniques.append({"id": "T1027", "name": "Obfuscated Files or Information"})
        seen.add("T1027")

    return techniques


def score_risk(conn, config=None):
    """
    Takes an enriched connection dict (output of enrich() + enrich_dns()) and
    returns a risk assessment dict with:
        score             - int 0-100
        label             - LOW / MEDIUM / HIGH / CRITICAL
        reasons           - list of strings explaining why
        attack_vectors    - (FR11) list of named attack categories that fit
        mitre_techniques  - (FR11) list of {id, name} dicts mapping to MITRE ATT&CK

    Pass in a config dict to override the on-disk one for testing.

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
    # (FR22) pull weights from config so they can be tuned without touching code
    if config is None:
        config = load_config()
    w = config["weights"]
    t = config["thresholds"]

    score = 0
    reasons = []
    fired = set()  # which heuristics fired, used by FR11 vector classification

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
        return {
            "score": 0,
            "label": "LOW",
            "reasons": ["Loopback connection, local traffic only."],
            "attack_vectors": [],
            "mitre_techniques": [],
        }

    # heuristic checks 

    # not in our known processes whitelist
    if not process_known:
        score += w["unknown_process"]
        reasons.append(f"'{conn.get('process_name')}' is not a recognized Windows process.")
        fired.add("unknown_process")

    # LOLBin / scripting engine making outbound connection
    # match on exact basename to avoid false positives on names like "my_powershell_wrapper.exe"
    process_basename = Path(process).name
    if process_basename in SUSPICIOUS_PROCESSES:
        score += w["lolbin"]
        reasons.append(f"'{process_basename}' is commonly abused by malware for command execution (LOLBin).")
        fired.add("lolbin")

    # looks like a system process but running from the wrong folder
    if process_basename in SPOOFABLE_PROCESSES and not _is_trusted_path(path):
        score += w["masquerading"]
        reasons.append(
            f"'{conn.get('process_name')}' looks like a system process but is running from "
            f"'{path}' instead of System32. Possible masquerading."
        )
        fired.add("masquerading")

    # enrich() checks if the process is on a port outside its expected_ports list
    if port_mismatch:
        score += w["port_mismatch"]
        reasons.append(
            f"'{conn.get('process_name')}' is using port {port} which isn't in its expected port list."
        )
        fired.add("port_mismatch")

    # port is flagged in known_ports.json
    if port_suspicious:
        score += w["port_suspicious"]
        reasons.append(f"Port {port} ({conn.get('service_name', 'unknown')}) is flagged as suspicious.")
        fired.add("port_suspicious")

    # can't verify where the process is running from
    if not path or path == "unknown":
        score += w["unknown_path"]
        reasons.append("Could not verify the process executable path.")
        fired.add("unknown_path")

    # clamp to 100 and assign label using the configurable thresholds
    score = min(score, 100)

    if score > t["high_max"]:
        label = "CRITICAL"
    elif score > t["medium_max"]:
        label = "HIGH"
    elif score > t["low_max"]:
        label = "MEDIUM"
    else:
        label = "LOW"

    if not reasons:
        reasons.append("No suspicious indicators found.")

    return {
        "score": score,
        "label": label,
        "reasons": reasons,
        "attack_vectors": _classify_attack_vectors(fired),
        "mitre_techniques": _map_mitre_techniques(fired, process_basename),
    }
