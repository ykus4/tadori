"""MITRE ATT&CK for Mobile technique table.

Generated from the MITRE CTI ``mobile-attack`` STIX bundle; used to
validate rule metadata and to label report output.
"""

from __future__ import annotations

import re

TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
MBC_ID_RE = re.compile(r"^(OB|B|C|E|F|M)\d{4}(\.\d{3})?$")

# technique id -> (name, tactics)
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1398": ("Boot or Logon Initialization Scripts", ("persistence",)),
    "T1404": ("Exploitation for Privilege Escalation", ("privilege-escalation",)),
    "T1406": ("Obfuscated Files or Information", ("defense-evasion",)),
    "T1406.001": ("Steganography", ("defense-evasion",)),
    "T1406.002": ("Software Packing", ("defense-evasion",)),
    "T1407": ("Download New Code at Runtime", ("defense-evasion",)),
    "T1409": ("Stored Application Data", ("collection",)),
    "T1414": ("Clipboard Data", ("collection", "credential-access")),
    "T1417": ("Input Capture", ("collection", "credential-access")),
    "T1417.001": ("Keylogging", ("collection", "credential-access")),
    "T1417.002": ("GUI Input Capture", ("collection", "credential-access")),
    "T1418": ("Software Discovery", ("discovery",)),
    "T1418.001": ("Security Software Discovery", ("discovery",)),
    "T1420": ("File and Directory Discovery", ("discovery",)),
    "T1421": ("System Network Connections Discovery", ("discovery",)),
    "T1422": ("System Network Configuration Discovery", ("discovery",)),
    "T1422.001": ("Internet Connection Discovery", ("discovery",)),
    "T1422.002": ("Wi-Fi Discovery", ("discovery",)),
    "T1423": ("Network Service Scanning", ("discovery",)),
    "T1424": ("Process Discovery", ("discovery",)),
    "T1426": ("System Information Discovery", ("discovery",)),
    "T1428": ("Exploitation of Remote Services", ("lateral-movement",)),
    "T1429": ("Audio Capture", ("collection",)),
    "T1430": ("Location Tracking", ("collection", "discovery")),
    "T1430.001": ("Remote Device Management Services", ("collection", "discovery")),
    "T1430.002": ("Impersonate SS7 Nodes", ("collection", "discovery")),
    "T1437": ("Application Layer Protocol", ("command-and-control",)),
    "T1437.001": ("Web Protocols", ("command-and-control",)),
    "T1451": ("SIM Card Swap", ("initial-access",)),
    "T1453": ("Abuse Accessibility Features", ("collection", "credential-access")),
    "T1456": ("Drive-By Compromise", ("initial-access",)),
    "T1458": (
        "Replication Through Removable Media",
        ("initial-access", "lateral-movement"),
    ),
    "T1461": ("Lockscreen Bypass", ("initial-access",)),
    "T1464": ("Network Denial of Service", ("impact",)),
    "T1471": ("Data Encrypted for Impact", ("impact",)),
    "T1474": ("Supply Chain Compromise", ("initial-access",)),
    "T1474.001": (
        "Compromise Software Dependencies and Development Tools",
        ("initial-access",),
    ),
    "T1474.002": ("Compromise Hardware Supply Chain", ("initial-access",)),
    "T1474.003": ("Compromise Software Supply Chain", ("initial-access",)),
    "T1481": ("Web Service", ("command-and-control",)),
    "T1481.001": ("Dead Drop Resolver", ("command-and-control",)),
    "T1481.002": ("Bidirectional Communication", ("command-and-control",)),
    "T1481.003": ("One-Way Communication", ("command-and-control",)),
    "T1509": ("Non-Standard Port", ("command-and-control",)),
    "T1512": ("Video Capture", ("collection",)),
    "T1513": ("Screen Capture", ("collection",)),
    "T1516": ("Input Injection", ("defense-evasion", "impact")),
    "T1517": ("Access Notifications", ("collection", "credential-access")),
    "T1521": ("Encrypted Channel", ("command-and-control",)),
    "T1521.001": ("Symmetric Cryptography", ("command-and-control",)),
    "T1521.002": ("Asymmetric Cryptography", ("command-and-control",)),
    "T1521.003": ("SSL Pinning", ("command-and-control",)),
    "T1532": ("Archive Collected Data", ("collection",)),
    "T1533": ("Data from Local System", ("collection",)),
    "T1541": ("Foreground Persistence", ("defense-evasion", "persistence")),
    "T1544": ("Ingress Tool Transfer", ("command-and-control",)),
    "T1575": ("Native API", ("defense-evasion", "execution")),
    "T1577": ("Compromise Application Executable", ("persistence",)),
    "T1582": ("SMS Control", ("impact",)),
    "T1603": ("Scheduled Task/Job", ("execution", "persistence")),
    "T1604": ("Proxy Through Victim", ("defense-evasion",)),
    "T1616": ("Call Control", ("collection", "command-and-control", "impact")),
    "T1617": ("Hooking", ("defense-evasion",)),
    "T1623": ("Command and Scripting Interpreter", ("execution",)),
    "T1623.001": ("Unix Shell", ("execution",)),
    "T1624": ("Event Triggered Execution", ("persistence",)),
    "T1624.001": ("Broadcast Receivers", ("persistence",)),
    "T1625": ("Hijack Execution Flow", ("persistence",)),
    "T1625.001": ("System Runtime API Hijacking", ("persistence",)),
    "T1626": ("Abuse Elevation Control Mechanism", ("privilege-escalation",)),
    "T1626.001": ("Device Administrator Permissions", ("privilege-escalation",)),
    "T1627": ("Execution Guardrails", ("defense-evasion",)),
    "T1627.001": ("Geofencing", ("defense-evasion",)),
    "T1628": ("Hide Artifacts", ("defense-evasion",)),
    "T1628.001": ("Suppress Application Icon", ("defense-evasion",)),
    "T1628.002": ("User Evasion", ("defense-evasion",)),
    "T1628.003": ("Conceal Multimedia Files", ("defense-evasion",)),
    "T1629": ("Impair Defenses", ("defense-evasion",)),
    "T1629.001": ("Prevent Application Removal", ("defense-evasion",)),
    "T1629.002": ("Device Lockout", ("defense-evasion",)),
    "T1629.003": ("Disable or Modify Tools", ("defense-evasion",)),
    "T1630": ("Indicator Removal on Host", ("defense-evasion",)),
    "T1630.001": ("Uninstall Malicious Application", ("defense-evasion",)),
    "T1630.002": ("File Deletion", ("defense-evasion",)),
    "T1630.003": ("Disguise Root/Jailbreak Indicators", ("defense-evasion",)),
    "T1631": ("Process Injection", ("defense-evasion", "privilege-escalation")),
    "T1631.001": ("Ptrace System Calls", ("defense-evasion", "privilege-escalation")),
    "T1632": ("Subvert Trust Controls", ("defense-evasion",)),
    "T1632.001": ("Code Signing Policy Modification", ("defense-evasion",)),
    "T1633": ("Virtualization/Sandbox Evasion", ("defense-evasion",)),
    "T1633.001": ("System Checks", ("defense-evasion",)),
    "T1634": ("Credentials from Password Store", ("credential-access",)),
    "T1634.001": ("Keychain", ("credential-access",)),
    "T1635": ("Steal Application Access Token", ("credential-access",)),
    "T1635.001": ("URI Hijacking", ("credential-access",)),
    "T1636": ("Protected User Data", ("collection",)),
    "T1636.001": ("Calendar Entries", ("collection",)),
    "T1636.002": ("Call Log", ("collection",)),
    "T1636.003": ("Contact List", ("collection",)),
    "T1636.004": ("SMS Messages", ("collection",)),
    "T1636.005": ("Accounts", ("collection",)),
    "T1637": ("Dynamic Resolution", ("command-and-control",)),
    "T1637.001": ("Domain Generation Algorithms", ("command-and-control",)),
    "T1638": ("Adversary-in-the-Middle", ("collection",)),
    "T1639": ("Exfiltration Over Alternative Protocol", ("exfiltration",)),
    "T1639.001": ("Exfiltration Over Unencrypted Non-C2 Protocol", ("exfiltration",)),
    "T1640": ("Account Access Removal", ("impact",)),
    "T1641": ("Data Manipulation", ("impact",)),
    "T1641.001": ("Transmitted Data Manipulation", ("impact",)),
    "T1642": ("Endpoint Denial of Service", ("impact",)),
    "T1643": ("Generate Traffic from Victim", ("impact",)),
    "T1644": ("Out of Band Data", ("command-and-control",)),
    "T1645": ("Compromise Client Software Binary", ("persistence",)),
    "T1646": ("Exfiltration Over C2 Channel", ("exfiltration",)),
    "T1655": ("Masquerading", ("defense-evasion",)),
    "T1655.001": ("Match Legitimate Name or Location", ("defense-evasion",)),
    "T1658": ("Exploitation for Client Execution", ("execution",)),
    "T1660": ("Phishing", ("initial-access",)),
    "T1661": ("Application Versioning", ("defense-evasion", "initial-access")),
    "T1662": ("Data Destruction", ("impact",)),
    "T1663": ("Remote Access Software", ("command-and-control",)),
    "T1664": ("Exploitation for Initial Access", ("initial-access",)),
    "T1670": ("Virtualization Solution", ("defense-evasion",)),
    "T1676": ("Linked Devices", ("collection", "persistence")),
}


def name_of(technique_id: str) -> str:
    """Human-readable name for a technique id, or the id itself if unknown."""
    entry = TECHNIQUES.get(technique_id)
    return entry[0] if entry else technique_id


def tactics_of(technique_id: str) -> tuple[str, ...]:
    entry = TECHNIQUES.get(technique_id)
    return entry[1] if entry else ()


def is_known(technique_id: str) -> bool:
    return technique_id in TECHNIQUES
