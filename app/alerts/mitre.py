"""
Static MITRE ATT&CK technique mapping.
Matches IOC type + log keywords → technique ID, name, tactic.
"""

# Order matters — first match wins
_KEYWORD_MAP = [
    (["Failed password", "sshd", "brute", "Invalid user", "authentication failure"],
     "T1110", "Brute Force", "Credential Access"),
    (["ransomware", "ransom", "encrypt", ".exe HTTP", "payload.exe"],
     "T1486", "Data Encrypted for Impact", "Impact"),
    (["beacon", "4444", "cobalt strike", "meterpreter", "C2", "command-and-control"],
     "T1071.001", "Web Protocols (C2)", "Command and Control"),
    (["phish", "steal.php", "phish-login", "credential harvest"],
     "T1566.002", "Spearphishing Link", "Initial Access"),
    (["nslookup", "dga", "named[", "query:"],
     "T1071.004", "DNS C2", "Command and Control"),
    (["exfil", "bytes=52428800", "bytes=104857", "upload", "FTP"],
     "T1041", "Exfiltration Over C2 Channel", "Exfiltration"),
    (["nmap", "masscan", "port sweep", "SYN scan"],
     "T1046", "Network Service Discovery", "Discovery"),
    (["tor", "onion", "exit node", "block-tor"],
     "T1090.003", "Multi-hop Proxy", "Command and Control"),
    (["EventCode=4688", "evil.exe", "cmd.exe", "powershell"],
     "T1204.002", "Malicious File Execution", "Execution"),
    (["ssl", "TRAFFIC ALLOW", "TRAFFIC DENY"],
     "T1071.001", "Web Protocols", "Command and Control"),
]

_TYPE_DEFAULTS = {
    "ip":     ("T1071",     "Application Layer Protocol", "Command and Control"),
    "domain": ("T1071.004", "DNS",                        "Command and Control"),
    "url":    ("T1071.001", "Web Protocols",               "Command and Control"),
    "md5":    ("T1204.002", "Malicious File",              "Execution"),
    "sha1":   ("T1204.002", "Malicious File",              "Execution"),
    "sha256": ("T1204.002", "Malicious File",              "Execution"),
}


def tag(ioc_type: str, source_log: str) -> dict:
    """Return {technique_id, technique_name, tactic}."""
    log = source_log or ""
    for keywords, tid, tname, tactic in _KEYWORD_MAP:
        if any(kw.lower() in log.lower() for kw in keywords):
            return {"technique_id": tid, "technique_name": tname, "tactic": tactic}
    if ioc_type in _TYPE_DEFAULTS:
        tid, tname, tactic = _TYPE_DEFAULTS[ioc_type]
        return {"technique_id": tid, "technique_name": tname, "tactic": tactic}
    return {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": "Command and Control"}
