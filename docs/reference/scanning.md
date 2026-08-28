# Enumeration & vulnerability identification

> Part of the [recce reference](../README.md) · back to the [project README](../../README.md).

## Service-aware NSE set

Both `enum` and `vulns` run a **service-aware** NSE set -- nmap executes only scripts whose portrule matches:

- **Web**: `http-enum`, `http-title`, `http-headers`, `http-methods`, `http-webdav-scan`, `http-git`, `http-auth`, `http-open-proxy`, `http-ntlm-info`, `http-wordpress-enum`, `http-devframework`, `http-config-backup`
- **TLS**: `ssl-cert`, `ssl-enum-ciphers`, `ssl-heartbleed`, `ssl-poodle`, `ssl-ccs-injection`, `ssl-dh-params`
- **SSH**: `ssh2-enum-algos`, `ssh-auth-methods`, `ssh-hostkey`
- **SMB/Windows**: `smb-vuln-ms17-010`, `smb-double-pulsar-backdoor`, `smb-enum-services`, `smb-system-info`, `smb2-capabilities`
- **FTP/mail**: `ftp-anon`, `ftp-vsftpd-backdoor`, `smtp-open-relay`, `smtp-enum-users`, `smtp-vuln-*`, POP3/IMAP caps + NTLM info
- **Databases**: `mysql-info`/`-databases`/`-users`/`-empty-password`, `ms-sql-*`, `oracle-tns-version`, `mongodb-info`/`-databases`, `redis-info`, `cassandra-info`
- **SNMP/DNS/misc**: `snmp-info`/`-win32-*`, `dns-zone-transfer`, `nfs-showmount`, `rpcinfo`, `vnc-info`, `rdp-ntlm-info`, `ike-version`, `ipmi-version`, `upnp-info`

**UDP** (needs root): `enum` sweeps 35 curated high-value UDP ports with `-sV` + cheap SNMP/DNS/NTP/NetBIOS/IKE scripts (DNS/DHCP/TFTP/rpcbind/NTP/NetBIOS/SNMP/CLDAP/SLP/IKE/Syslog/RIP/IPMI/IPP/OpenVPN/RADIUS/L2TP/NFS/STUN/SSDP/SIP/mDNS/LLMNR/CoAP/memcached/VxWorks/BACnet). `vulns` adds broader top-N with `--udp-top N` (**thorough** runs 100). Skip with `--no-udp`.

## Four vulnerability channels (all airgapped)

1. **NSE `vuln` category + weak-config findings** from enumeration scripts -- anonymous FTP, weak/expired TLS, risky HTTP methods, empty DB passwords, cleartext Telnet, SMTP open relay, exposed Redis/Mongo, SNMP community strings, DNS zone transfer, etc.

2. **Offline version-to-CVE engine** (`vulndb.py`) -- **108 high-signal signatures** matching product+version against known CVEs with description, CWE(s), and remediation. Covers FTP/SSH/web servers, Samba/SMB, databases, CI/web apps (Jenkins, Tomcat, Drupal, Confluence, GitLab, Grafana), **edge/VPN/firewall appliances** (Fortinet, Pulse/Ivanti, Citrix, Palo Alto, SonicWall, F5, Cisco ASA/Smart Install, MikroTik, Zyxel, DrayTek, Sophos, Barracuda), Exchange, **virtualization** (vCenter, ESXi, Horizon), **Java middleware** (WebLogic, JBoss, ActiveMQ, ColdFusion, Solr, Zimbra, Jetty), **dev/CI/infra** (Docker API, Kubernetes/kubelet, etcd, Nexus, TeamCity, SonarQube), **monitoring** (Zabbix, Cacti, PRTG, Nagios, CouchDB, Kibana, Splunk), **OS-gated Windows/AD** (SMBGhost, PrintNightmare, ZeroLogon, WinRM, MSSQL), and default-credential advisories. Airgapped replacement for nmap's `vulners` script. Findings tagged `likely` (version range match) or `potential` (product-only/OS-gated lead).

3. **Pure-Python probes** (`probes.py`, stdlib only) -- **HTTP security-header analysis** (missing HSTS/CSP/X-Frame-Options/X-Content-Type-Options, version-disclosing `Server` banners) and **TLS cert & protocol analysis** (expired/self-signed/soon-to-expire certs, hostname mismatch, SSLv3/TLS 1.0/1.1). Disable with `--no-probes`. The web sweep (`web.py`) also carries **application signatures** with self-proving unauth paths: **Jenkins** (unauth script-console RCE), **Keycloak**, **Grafana** (CVE-2021-43798), **Vault**, **Elasticsearch** (unauth index read), **Kibana**, plus `.git`/`.env`, Spring Actuator, Tomcat Manager. `--creds` runs lockout-aware **default-credential** probes (HTTP Basic + form/JSON: Grafana `admin/admin`, MinIO `minioadmin`, RabbitMQ `guest/guest`). `--crawl` same-origin crawls and fuzzes **discovered params/forms** for reflection/SSTI, **SQL injection** (error-based MySQL/PostgreSQL/MSSQL/Oracle/SQLite, boolean-based blind with re-test, opt-in time-based `--sqli-time`), **open redirect**, and **path traversal/LFI**. Payloads non-destructive; password/anti-CSRF fields never touched. **Cookies** graded (HttpOnly/Secure/SameSite, session over cleartext, `__Host-`/`__Secure-` prefix, over-broad `Domain`). Confirmed SQLi **bridges to pre-filled `sqlmap`**. Also runs **content/directory discovery** (curated wordlist; SPA/catch-all suppressed) and **vhost enumeration** (candidates from TLS cert SAN/CN, reverse DNS, nmap hostname; Host-header probed).

4. **`searchsploit` (Exploit-DB, offline)** maps product+version to public exploits on the **Exploits** sheet (EDB-ID, type, title, CVEs, local path).

Every finding carries **CWE** references alongside CVEs.

## Fix-first ranking

Findings ranked by **fix-first** priority. Each CVE checked against **CISA KEV** (exploited-in-the-wild sorts to top, above CVSS) and **EPSS** 30-day exploitation probability; severity x QoD breaks remaining ties. Both ship as **offline snapshots** (refreshed at build).

> **Airgapped tip:** `--offline` drops the `vulners` script; local `vuln` category, weak-config findings, offline version-to-CVE, HTTP/TLS probes, and `searchsploit` all still work. Install `exploitdb` for searchsploit (`apt install exploitdb`; ships on Kali).

Toggles (on `vulns`/`scan`): `--aggressive`, `--offline`, `--no-searchsploit`, `--no-probes`, `--udp-top N`, plus positional targets, `--only`, `--unscanned`.
