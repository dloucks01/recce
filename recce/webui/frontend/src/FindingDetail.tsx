import { useState } from "react";
import { VulnDetail } from "./api";
import { SevTag, NoteCell } from "./ui";

function CopyBtn({ text, label }: { text: string; label: string }) {
  const [ok, setOk] = useState(false);
  return (
    <button
      className="fd-copy"
      onClick={() => {
        navigator.clipboard?.writeText(text).then(() => {
          setOk(true);
          setTimeout(() => setOk(false), 1200);
        });
      }}
    >
      {ok ? "Copied" : label}
    </button>
  );
}

interface Suggestion {
  label: string;
  cmd: string;
  note?: string;
}

function getSuggestions(v: VulnDetail): Suggestion[] {
  const out: Suggestion[] = [];
  const t = v.title.toLowerCase();
  const ip = v.ip;
  const port = v.port;

  if (v.cve) {
    out.push({ label: "Search for public exploits", cmd: `searchsploit ${v.cve}`, note: "local exploit-db" });
    out.push({ label: "Search Metasploit modules", cmd: `msfconsole -q -x "search ${v.cve}; exit"` });
  }

  if (t.includes("smb signing") || t.includes("smb message signing")) {
    out.push({ label: "NTLM relay (if you have creds)", cmd: `ntlmrelayx.py -t ${ip} -smb2support`, note: "relay captured auth" });
    out.push({ label: "Enumerate SMB shares", cmd: `smbclient -L //${ip} -N` });
  }
  if (t.includes("anonymous") && port === 21) {
    out.push({ label: "Browse FTP anonymously", cmd: `ftp ${ip}` });
  }
  if (t.includes("anonymous") && (port === 445 || t.includes("smb"))) {
    out.push({ label: "List shares anonymously", cmd: `smbclient -L //${ip} -N` });
    out.push({ label: "Null session RPC", cmd: `rpcclient -U '' -N ${ip}` });
  }
  if (port === 445 || t.includes("smb") || t.includes("samba")) {
    if (!out.some(s => s.cmd.includes("smbclient"))) {
      out.push({ label: "Enumerate SMB", cmd: `crackmapexec smb ${ip} --shares` });
    }
  }
  if (t.includes("ms17-010") || t.includes("eternalblue")) {
    out.push({ label: "EternalBlue exploit", cmd: `msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS ${ip}; run; exit"` });
  }
  if (t.includes("printnightmare") || t.includes("cve-2021-34527")) {
    out.push({ label: "PrintNightmare exploit", cmd: `python3 CVE-2021-34527.py ${ip}`, note: "needs valid creds" });
  }
  if (t.includes("zerologon") || t.includes("cve-2020-1472")) {
    out.push({ label: "Zerologon check", cmd: `python3 zerologon_tester.py DC_NAME ${ip}` });
  }
  if (t.includes("kerberoast") || t.includes("spn")) {
    out.push({ label: "Kerberoast SPNs", cmd: `GetUserSPNs.py DOMAIN/user:pass -dc-ip ${ip} -request` });
  }
  if (t.includes("asrep") || t.includes("preauth")) {
    out.push({ label: "AS-REP roast", cmd: `GetNPUsers.py DOMAIN/ -dc-ip ${ip} -usersfile users.txt -no-pass` });
  }
  if (t.includes("ldap") && (t.includes("sign") || t.includes("bind"))) {
    out.push({ label: "LDAP enumeration", cmd: `ldapsearch -x -H ldap://${ip} -b "dc=domain,dc=local"` });
  }
  if (port === 3389 || t.includes("rdp")) {
    out.push({ label: "RDP brute-force", cmd: `hydra -l admin -P /usr/share/wordlists/rockyou.txt ${ip} rdp` });
  }
  if (port === 22 || t.includes("ssh")) {
    out.push({ label: "SSH brute-force", cmd: `hydra -l root -P /usr/share/wordlists/rockyou.txt ${ip} ssh` });
  }
  if (t.includes("default") && (t.includes("credential") || t.includes("password"))) {
    out.push({ label: "Try default credentials", cmd: `crackmapexec smb ${ip} -u admin -p admin` });
  }
  if (t.includes("snmp") && (t.includes("community") || t.includes("public"))) {
    out.push({ label: "SNMP walk", cmd: `snmpwalk -v2c -c public ${ip}` });
  }
  if (port === 80 || port === 443 || port === 8080 || port === 8443 || t.includes("http")) {
    const scheme = (port === 443 || port === 8443) ? "https" : "http";
    const p = port || 80;
    out.push({ label: "Directory brute-force", cmd: `gobuster dir -u ${scheme}://${ip}:${p}/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` });
  }
  if (t.includes("sql injection") || t.includes("sqli")) {
    out.push({ label: "SQLMap scan", cmd: `sqlmap -u "http://${ip}${port ? ':' + port : ''}/" --batch --dbs` });
  }

  if (v.cves && v.cves.length > 0 && out.length === 0) {
    out.push({ label: "Search for exploits", cmd: `searchsploit ${v.cves[0]}` });
  }

  if (port && out.length === 0) {
    out.push({ label: "Enumerate this service", cmd: `nmap -sV -sC -p ${port} ${ip}` });
  }

  return out;
}

function getImpact(v: VulnDetail): string | null {
  const sev = v.severity;
  const t = v.title.toLowerCase();

  if (v.kev) return "This vulnerability is in CISA's Known Exploited Vulnerabilities catalog — confirmed exploited in the wild. Prioritize remediation.";
  if (sev === "critical" && v.cve) return "Critical severity with a public CVE. Likely has published exploit code. This host should be considered at high risk of compromise.";
  if (sev === "critical") return "Critical severity finding. This could lead directly to system compromise, data exfiltration, or lateral movement.";
  if (t.includes("smb signing")) return "SMB signing is disabled, enabling NTLM relay attacks. An attacker with network position can relay authentication to gain access.";
  if (t.includes("eternalblue") || t.includes("ms17-010")) return "EternalBlue gives unauthenticated remote code execution as SYSTEM. This is a direct path to full host compromise.";
  if (t.includes("zerologon")) return "Zerologon allows unauthenticated domain controller takeover. This is a critical path to Domain Admin.";
  if (t.includes("printnightmare")) return "PrintNightmare allows authenticated remote code execution as SYSTEM via the print spooler service.";
  if (t.includes("kerberoast")) return "Kerberoastable service accounts can have their passwords cracked offline. If a privileged account is kerberoastable, it's a path to escalation.";
  if (t.includes("anonymous") && t.includes("ftp")) return "Anonymous FTP access may expose sensitive files, credentials, or configuration data.";
  if (t.includes("default") && (t.includes("credential") || t.includes("password"))) return "Default credentials provide immediate authenticated access. Check for privilege escalation paths from this foothold.";
  if (sev === "high") return "High severity finding that may enable further exploitation, lateral movement, or data access.";
  if (sev === "medium") return "Medium severity finding. May require additional conditions to exploit but could contribute to an attack chain.";
  return null;
}

export function FindingDetail(
  { v, onNote, onAddToReport, onJumpToHost }: {
    v: VulnDetail;
    onNote: (key: string, text: string) => void;
    onAddToReport?: (key: string) => void;
    onJumpToHost?: (ip: string) => void;
  }
) {
  const suggestions = getSuggestions(v);
  const impact = getImpact(v);

  return (
    <div className="dv-detail">
      {/* Metadata */}
      <div className="fd-meta">
        <div className="fd-meta-row">
          <SevTag severity={v.severity} />
          {v.source && <span className="fd-source">{v.source}</span>}
          {v.tier && <span className={"fd-tier tier " + v.tier}>{v.tier}</span>}
          {v.kev && <span className="badge kev">KEV</span>}
        </div>
        <div className="fd-kv">
          {v.port != null && (
            <div className="fd-kv-item">
              <span className="fd-kv-label">Port</span>
              <span className="fd-kv-value mono">{v.port}</span>
            </div>
          )}
          <div className="fd-kv-item">
            <span className="fd-kv-label">Quality</span>
            <span className="fd-kv-value mono">{v.qod}{v.qod_type ? ` ${v.qod_type}` : ""}</span>
          </div>
          {v.epss > 0 && (
            <div className="fd-kv-item">
              <span className="fd-kv-label">EPSS</span>
              <span className="fd-kv-value mono">{v.epss}%</span>
            </div>
          )}
          {v.cwes.length > 0 && (
            <div className="fd-kv-item">
              <span className="fd-kv-label">CWE</span>
              <span className="fd-kv-value mono">{v.cwes.join(", ")}</span>
            </div>
          )}
          {v.cve && (
            <div className="fd-kv-item">
              <span className="fd-kv-label">CVE</span>
              <span className="fd-kv-value mono">{v.cve}</span>
            </div>
          )}
          <div className="fd-kv-item">
            <span className="fd-kv-label">Host</span>
            <span className="fd-kv-value mono fd-host-link"
                  onClick={() => onJumpToHost?.(v.ip)}
                  title="Open host detail">{v.ip}</span>
          </div>
        </div>
      </div>

      {/* Impact summary */}
      {impact && (
        <div className="fd-impact">
          <span className="fd-section-label">Operational Impact</span>
          <p className="fd-impact-text">{impact}</p>
        </div>
      )}

      {/* Evidence */}
      {v.output && (
        <div className="fd-evidence">
          <div className="fd-evidence-header">
            <span className="fd-section-label">Evidence / Tool Output</span>
            <CopyBtn text={v.output} label="Copy" />
          </div>
          <pre className="fd-evidence-code">{v.output}</pre>
        </div>
      )}

      {/* Next steps */}
      {suggestions.length > 0 && (
        <div className="fd-nextsteps">
          <span className="fd-section-label">Next Steps</span>
          <div className="fd-suggestions">
            {suggestions.map((s, i) => (
              <div key={i} className="fd-suggestion">
                <div className="fd-sugg-header">
                  <span className="fd-sugg-label">{s.label}</span>
                  {s.note && <span className="fd-sugg-note">{s.note}</span>}
                  <CopyBtn text={s.cmd} label="Copy cmd" />
                </div>
                <code className="fd-sugg-cmd">{s.cmd}</code>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Remediation */}
      {v.remediation && (
        <div className="fd-remediation">
          <span className="fd-section-label">Remediation</span>
          <div className="fd-remediation-body">{v.remediation}</div>
        </div>
      )}

      {/* Actions */}
      <div className="fd-actions">
        <span className="fd-section-label">Actions</span>
        <div className="fd-action-row">
          {v.output && <CopyBtn text={v.output} label="Copy output" />}
          {v.cves && v.cves.length > 0 && (
            <CopyBtn text={v.cves.join(", ")} label={`Copy ${v.cves.length > 1 ? "CVEs" : "CVE"}`} />
          )}
          {v.remediation && <CopyBtn text={v.remediation} label="Copy fix" />}
          {onJumpToHost && (
            <button className="fd-copy fd-action-nav" onClick={() => onJumpToHost(v.ip)}>
              Jump to host
            </button>
          )}
          {onAddToReport && (
            <button className="fd-copy fd-action-report" onClick={() => onAddToReport(v.key)}>
              + Add to report
            </button>
          )}
        </div>
      </div>

      {/* Notes */}
      <div className="fd-notes">
        <span className="fd-section-label">Notes</span>
        <NoteCell value={v.notes} onSave={(t) => onNote(v.key, t)} />
      </div>
    </div>
  );
}
