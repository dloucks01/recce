# Privilege escalation & exploitation

## Priv-Esc (`privesc`)

Produces a per-host **Priv-Esc** sheet with two parts:

- **Remote findings** — missing patches with public exploits (MS17-010, ZeroLogon, BlueKeep, PrintNightmare), SMB signing off, unauthenticated services, searchsploit candidates
- **OS-specific playbook** — prioritized checks for post-foothold. Windows: winPEAS/PowerUp, service perms, `AlwaysInstallElevated`, token privileges, stored creds. Linux: linPEAS, `sudo -l`+GTFOBins, SUID/SGID, capabilities, cron, NFS `no_root_squash`, docker/lxd group

Generated offline from `enum` data; `--scan` adds remote NSE checks.

## On-target enum and `ingest`

recce ships read-only on-target sweeps in `recce/local/` — `recce-enum.sh` (Linux) and `recce-enum.ps1` (Windows). Run on target, bring back the output, fold it in:

```bash
# on target:
./recce-enum.sh -o loot.txt
# on Kali:
recce ingest loot.txt -o eng     # auto-resolves host; --host IP to force
```

Host resolution is automatic via interface IPs from the enum's `NETWORK` block. The topology data (`NET-IFACE/ROUTE/NEIGH/PEER`) feeds `network-reachability.svg` and `network-architecture.svg`.

## Exploit plan (`exploitplan`)

For each confirmed finding, writes ready-to-run artifacts into `eng/exploit-plan/`:

- **Metasploit `.rc` files** with RHOSTS/RPORT/PAYLOAD/LHOST set — `ms17_010_eternalblue`, `vsftpd_234_backdoor`, SambaCry, etc. Launch line is commented out until `--run`.
- **Tool commands** — impacket, ntlmrelayx, anonymous FTP, unauth Redis, etc. — with parameters pre-filled
- Per-host `<ip>.sh` chaining remote steps + post-shell priv-esc

Gated to confirmed findings, safe by default. Everything is within rules of engagement.

**AV/EDR awareness.** When you `ingest` a `recce-enum.ps1` run, recce records the host's defensive posture (Defender, EDR agents, Sysmon, LSASS RunAsPPL, AppLocker, Credential Guard) and shows it on the Exploitation sheet. recce flags what's watching — it does not evade AV/EDR.
