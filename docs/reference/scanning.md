# Enumeration & vulnerability identification

The service-aware NSE set recce runs, the four offline vulnerability channels that feed the Vulnerabilities sheet, and the fix-first (KEV/EPSS) ranking.

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Enumeration & vulnerability identification

Both `enum` (deep enumeration) and `vulns` run a large, **service-aware** NSE set —
nmap only executes the scripts whose portrule matches each detected service, so
coverage is broad but cheap. Highlights:

- **Web**: `http-enum`, `http-title`, `http-headers`, `http-methods`,
  `http-webdav-scan`, `http-git`, `http-auth`, `http-open-proxy`, `http-ntlm-info`,
  `http-wordpress-enum`, `http-devframework`, `http-config-backup`
- **TLS**: `ssl-cert`, `ssl-enum-ciphers`, `ssl-heartbleed`, `ssl-poodle`,
  `ssl-ccs-injection`, `ssl-dh-params` (weak ciphers/protocols, known TLS CVEs)
- **SSH**: `ssh2-enum-algos`, `ssh-auth-methods`, `ssh-hostkey`
- **SMB/Windows**: `smb-vuln-ms17-010`, `smb-double-pulsar-backdoor`,
  `smb-enum-services`, `smb-system-info`, `smb2-capabilities`
- **FTP/mail**: `ftp-anon`, `ftp-vsftpd-backdoor`, `smtp-open-relay`,
  `smtp-enum-users`, `smtp-vuln-*`, POP3/IMAP caps + NTLM info
- **Databases**: `mysql-info`/`-databases`/`-users`/`-empty-password`, `ms-sql-*`,
  `oracle-tns-version`, `mongodb-info`/`-databases`, `redis-info`, `cassandra-info`
- **SNMP/DNS/misc**: `snmp-info`/`-win32-*`, `dns-zone-transfer`, `nfs-showmount`,
  `rpcinfo`, `vnc-info`, `rdp-ntlm-info`, `ike-version`, `ipmi-version`, `upnp-info`

**UDP** (needs root): `enum` sweeps a curated set of 35 high-value UDP ports with
`-sV` + the cheap SNMP/DNS/NTP/NetBIOS/IKE scripts (DNS/DHCP/TFTP/rpcbind/NTP/NetBIOS/
SNMP/CLDAP/SLP/IKE/Syslog/RIP/IPMI/IPP/OpenVPN/RADIUS/L2TP/NFS/STUN/SSDP/SIP/mDNS/LLMNR/
CoAP/memcached/VxWorks/BACnet) — the default UDP coverage. `vulns` can add a broader
top-N UDP sweep with `--udp-top N` (opt-in; **thorough** runs 100). Skip all UDP with
`--no-udp`.

**Four vulnerability channels feed the Vulnerabilities sheet** (all work
airgapped, none need internet):

1. **NSE `vuln` category** (local) plus **weak-config findings** parsed from the
   enumeration scripts above — anonymous FTP, weak/expired TLS, risky HTTP
   methods, empty DB passwords, cleartext Telnet, SMTP open relay, exposed
   Redis/Mongo, SNMP community strings, DNS zone transfer, etc.
2. **Offline version→CVE engine** (`vulndb.py`) — a curated knowledge base of
   **108 high-signal signatures** that matches the product+version data `enum`
   already collected against known CVEs, with a description, CWE(s) and
   **remediation**. Covers FTP/SSH/web servers, Samba/SMB, databases, CI/web apps
   (Jenkins, Tomcat, Drupal, Confluence, GitLab, Grafana…), **edge/VPN/firewall
   appliances (Fortinet, Pulse/Ivanti, Citrix, Palo Alto, SonicWall, F5 BIG-IP,
   Cisco ASA/Smart Install, MikroTik, Zyxel, DrayTek, Sophos, Barracuda)**,
   Exchange, **virtualization (vCenter,
   ESXi, Horizon), Java middleware (WebLogic, JBoss, ActiveMQ, ColdFusion, Solr,
   Zimbra, Jetty), dev/CI/infra exposure (Docker API, Kubernetes/kubelet, etcd,
   Nexus, TeamCity, SonarQube), monitoring (Zabbix, Cacti, PRTG, Nagios, CouchDB,
   Kibana, Splunk), OS-gated Windows/AD advisories (SMBGhost, PrintNightmare,
   ZeroLogon, WinRM, MSSQL)**, and default-credential advisories. This is the
   airgapped replacement for nmap's internet-only `vulners` script. Findings are
   tagged `likely` (a concrete version range matched) or `potential` (a
   product-only or OS-gated advisory lead).
3. **Pure-Python enrichment probes** (`probes.py`, stdlib only) — an active
   layer stock Kali needs extra tooling (testssl.sh, nikto, httpx) for:
   **HTTP security-header analysis** (missing HSTS/CSP/X-Frame-Options/
   X-Content-Type-Options, version-disclosing `Server` banners) and **TLS
   certificate & protocol analysis** (expired/self-signed/soon-to-expire certs,
   hostname mismatch, negotiable SSLv3/TLS 1.0/1.1). Disable with `--no-probes`.
   The web sweep (`web.py`) also carries **data-driven application signatures** —
   fingerprint + a self-proving unauthenticated path — for high-value apps:
   **Jenkins** (unauth script-console RCE), **Keycloak** (admin console),
   **Grafana** (CVE-2021-43798 file read), **HashiCorp Vault**, **Elasticsearch**
   (unauth index read), **Kibana**, plus exposed `.git`/`.env`, Spring Actuator
   and Tomcat Manager. With `--creds` it runs a bounded, lockout-aware
   **default-credential** probe (HTTP Basic + form/JSON logins: Grafana
   `admin/admin`, MinIO `minioadmin`, RabbitMQ `guest/guest`). With `--crawl`
   it same-origin crawls each site and fuzzes **discovered GET params and form
   fields** for reflection/SSTI and **SQL injection** — error-based (MySQL/
   PostgreSQL/MSSQL/Oracle/SQLite error signatures), boolean-based blind
   (true≈baseline vs false-diverges, re-tested, skipped on dynamic pages), and
   opt-in time-based blind (`--sqli-time`), plus **open redirect** and generic
   **path traversal / local file read** on the same params/fields. Payloads are
   non-destructive (quote-break + `AND`/sleep, traversal reads only; never
   stacked `DROP`/`UPDATE`/`DELETE`); destructive-looking forms and
   password/anti-CSRF fields are never touched. Every response's **cookies** are
   graded too — missing HttpOnly/Secure/SameSite, `SameSite=None` without Secure,
   a session cookie over cleartext HTTP, a missing `__Host-`/`__Secure-` prefix,
   or an over-broad parent `Domain`. A **confirmed** SQLi isn't handed a
   reimplemented exploiter — recce **bridges to a pre-filled `sqlmap` command**
   (in the Act plan and the exploit plan) so you weaponise it with the purpose-built
   tool, within your ROE. The active web scan also runs **content/directory
   discovery** (a curated wordlist — admin panels, API/Swagger, dev/debug, dumps,
   listings; exposed files become their own findings, other hits roll up, and a
   200-everything SPA/catch-all is detected and suppressed so it never floods) and
   **virtual-host enumeration** (candidate names from the TLS cert SAN/CN, reverse
   DNS and the nmap hostname are probed via Host-header; a site that differs from the
   default response is reported as a distinct vhost to scan by name).
4. **`searchsploit` (Exploit-DB, offline)** maps every service's product+version
   to known public exploits on a dedicated **Exploits** sheet (EDB-ID, type,
   title, CVEs, local path).

Every finding also carries **CWE** references (in a dedicated column) alongside
its CVEs, so you can group and report weaknesses by class.

Findings are ranked **fix-first**, not just by severity. Each CVE is checked against
**CISA KEV** (Known Exploited Vulnerabilities) and carries its **EPSS** 30-day
exploitation probability. A KEV finding is flagged **🔥 KEV** and sorts to the **top**
— above raw CVSS — because confirmed exploited-in-the-wild is the strongest "fix this
first" signal; **EPSS** then orders what's most likely to be attacked next, and
severity × QoD breaks the remaining ties. Both KEV and EPSS ship as **offline
snapshots** (refreshed at package build), so prioritisation works airgapped.

> **Airgapped tip:** run with `--offline` to drop the internet-dependent
> `vulners` script; you still get the local `vuln` category, all weak-config
> findings, the offline version→CVE engine, the HTTP/TLS probes, and
> `searchsploit` exploit mapping. Install `exploitdb` for searchsploit
> (`apt install exploitdb`, and it ships on Kali).

Toggles (on `vulns`/`scan`): `--aggressive`, `--offline`, `--no-searchsploit`,
`--no-probes`, `--udp-top N`, plus positional targets, `--only`, `--unscanned`
to target a subset.


