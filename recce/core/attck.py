"""Best-effort MITRE ATT&CK technique inference from a command string.

Auto-tags the operations log so the team view and the report get technique mapping
without hand-labelling every post-ex action. Conservative: returns "" when nothing
matches, and it never overrides a technique an operator set explicitly. This is a
labelling aid, not a substitute for analyst review.
"""
from __future__ import annotations

import re

# (pattern, "Txxxx Name"), matched against the lowercased command, most-specific
# first (first match wins). Credential/roasting rules precede the generic
# discovery/data rules so e.g. `cat /etc/shadow` maps to credential access, not
# "data from local system".
_RULES: list[tuple[str, str]] = [
    (r"secretsdump|mimikatz|lsass|gsecdump|\bhashdump\b|dpapi|vaultcmd", "T1003 OS Credential Dumping"),
    (r"/etc/shadow|/etc/passwd", "T1003.008 /etc/passwd and /etc/shadow"),
    (r"reg (save|query).*sam|\bsam\b.*\bsystem\b", "T1003.002 Security Account Manager"),
    (r"kerberoast|getuserspns|\btgs-rep\b", "T1558.003 Kerberoasting"),
    (r"asreproast|getnpusers|as-rep", "T1558.004 AS-REP Roasting"),
    (r"\.bash_history|\.ssh/|id_rsa|id_ed25519|known_hosts|\.aws/credentials|unattend\.xml", "T1552 Unsecured Credentials"),
    (r"\bwhoami\b|\bid\b(?![\w-])", "T1033 System Owner/User Discovery"),
    (r"net user|net group|net localgroup|\bgetent\b|\bdscl\b", "T1087 Account Discovery"),
    (r"ipconfig|ifconfig|\bip a\b|\bip addr|/sbin/route|\barp -a", "T1016 System Network Configuration Discovery"),
    (r"netstat|\bss -[a-z]|lsof -i|sockstat", "T1049 System Network Connections Discovery"),
    (r"systeminfo|\buname\b|/etc/os-release|hostnamectl|\bsw_vers\b", "T1082 System Information Discovery"),
    (r"tasklist|\bps -[a-z]|\bps aux|get-process", "T1057 Process Discovery"),
    (r"net view|nbtstat|smbclient -l|showmount", "T1135 Network Share Discovery"),
    (r"schtasks|\bcrontab\b|systemctl.*\.timer|\bat \d", "T1053 Scheduled Task/Job"),
    (r"sudo -l|getcap|find / .*-perm|\bsuid\b|linpeas|winpeas|powerup", "T1068 Exploitation for Privilege Escalation"),
    (r"iptables|\bufw \b|netsh advfirewall|firewall-cmd", "T1562.004 Disable or Modify System Firewall"),
    (r"\bwget\b|curl .*-o|certutil.*urlcache|invoke-webrequest|\bscp \b|\btftp\b", "T1105 Ingress Tool Transfer"),
    (r"\bnmap\b|masscan|for .*ping ", "T1046 Network Service Discovery"),
    (r"base64 |\bxxd \b|\bcat \b|\btype \b|\bcopy \b|\bdd if=", "T1005 Data from Local System"),
]
_COMPILED = [(re.compile(p), t) for p, t in _RULES]


def technique_for(command: str) -> str:
    """The most likely ATT&CK technique for a post-ex command, or "" if unknown."""
    if not command:
        return ""
    low = command.lower()
    for rx, tech in _COMPILED:
        if rx.search(low):
            return tech
    return ""
