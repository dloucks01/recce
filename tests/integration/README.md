# Credentialed AD integration

`tests/test_credentialed_ad_integration.py` exercises recce's **authenticated** Active
Directory flows against a **real** domain controller — the one tier that can't be faked
with an in-process responder because it needs a live KDC / SAM / NTDS:

- authenticated SMB enumeration (`netexec`),
- **Kerberoasting via recce's native stdlib Kerberos client** (no impacket): SPN
  discovery over LDAP, then an RC4-HMAC TGS roast that captures a real, crackable
  `$krb5tgs$23$` hash,
- the BloodHound live-roast path (also native),
- the LDAP RootDSE probe reading the real domain,
- `secretsdump` (impacket) — dumps NTLM hashes as a domain admin.

The DC is a **Samba AD DC** in Docker (`docker-compose.ad.yml`), self-provisioning the
`RECCE.LOCAL` domain; `provision-ad.sh` then adds a Kerberoastable service account.

## Expected result against the Samba DC

**5 passed, 1 xfailed.** The one expected failure is `test_secretsdump_dumps_domain_hashes`:
impacket's DRSUAPI/DCSync is rejected by Samba's replication interface (a well-known
impacket-vs-Samba incompatibility, not a recce defect — recce has no native DCSync). It
is marked `@expectedFailure` and should **xpass against a real Windows DC** (below), which
is the signal that DRSUAPI works there.

## Gating

The test is inert by default. It runs **only** when `RECCE_AD_IT=1` **and** the DC is
reachable **and** the tools (`nxc`, `impacket-*`) are installed — otherwise it skips
cleanly, so it never affects the normal `pytest` run or a box without Docker.

## Run it locally (Samba DC)

```bash
docker compose -f tests/integration/docker-compose.ad.yml up -d
./tests/integration/provision-ad.sh

RECCE_AD_IT=1 \
RECCE_AD_HOST=127.0.0.1 \
RECCE_AD_DOMAIN=RECCE.LOCAL \
RECCE_AD_ADMIN=Administrator \
RECCE_AD_PASS='Recce!Passw0rd' \
RECCE_AD_SPN_USER=svc_sql \
  python -m pytest tests/test_credentialed_ad_integration.py -v

docker compose -f tests/integration/docker-compose.ad.yml down -v
```

Requires `netexec` and `impacket` on the host running the tests
(`pip install impacket netexec`).

## Validating against a real Windows DC

recce's native AD paths (LDAP-over-TLS bind, RC4 Kerberoasting) are validated against
Samba above, but Windows and Samba differ in LDAP signing policy, supported Kerberos
encryption types, and — crucially — DRSUAPI. A Windows run confirms the native paths
against the real target and should turn the secretsdump xfail into an **xpass**. This is
a **manual** gate (Windows Server licensing makes it impractical in CI).

1. **Stand up a DC.** A Windows Server evaluation VM (180-day eval ISO) is enough.
   Promote it to a domain controller:

   ```powershell
   Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
   Install-ADDSForest -DomainName recce.local -InstallDNS -Force
   ```

2. **Add a Kerberoastable service account** (mirrors `provision-ad.sh`):

   ```powershell
   New-ADUser -Name svc_sql -AccountPassword (ConvertTo-SecureString 'Sql!Passw0rd' -AsPlainText -Force) -Enabled $true
   setspn -a MSSQLSvc/db.recce.local:1433 svc_sql
   ```

   To also exercise the RC4 roast on a hardened DC, ensure the account permits RC4
   (`Set-ADUser svc_sql -KerberosEncryptionType RC4,AES128,AES256`); a modern native
   client also handles AES tickets, but the `$krb5tgs$23$` hash needs RC4.

3. **Point the test at it** from the Kali/test host (network route to the DC required):

   ```bash
   RECCE_AD_IT=1 \
   RECCE_AD_HOST=<windows-dc-ip> \
   RECCE_AD_DOMAIN=RECCE.LOCAL \
   RECCE_AD_ADMIN=Administrator \
   RECCE_AD_PASS='<DA-password>' \
   RECCE_AD_SPN_USER=svc_sql \
   RECCE_AD_SPN_PASS='Sql!Passw0rd' \
     python -m pytest tests/test_credentialed_ad_integration.py -v
   ```

4. **What to confirm:**
   - the native LDAP bind succeeds over **636/LDAPS** (Windows refuses a cleartext
     simple bind under default signing policy — `_spn_targets_native` tries 636 first);
   - native Kerberoasting captures a `$krb5tgs$23$` hash the service password cracks;
   - `test_secretsdump_dumps_domain_hashes` **xpasses** (DRSUAPI works on Windows).

   A green run here (5 pass + 1 **xpass**) is the sign-off that the native AD stack works
   against a production-style DC, not just Samba.

## CI

The `ad-integration` job in `.github/workflows/ci.yml` stands up the Samba DC, provisions
it, and runs this test on master pushes / nightly. It's a real signal now — **5 pass + 1
documented xfail** (secretsdump) — validated locally against the Samba DC. It stays
`continue-on-error` only because Samba DC provisioning **on a GitHub runner** hasn't yet
been confirmed reliable (timing/DNS); flip that off once a few runner builds are green.
