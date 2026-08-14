# Credentialed AD integration

`tests/test_credentialed_ad_integration.py` exercises recce's **authenticated** Active
Directory flows against a **real** domain controller — the one tier that can't be faked
with an in-process responder because it needs a live KDC / SAM / NTDS:

- authenticated SMB enumeration (`netexec`),
- Kerberoasting (`impacket-GetUserSPNs -request`) — captures a real TGS-REP hash,
- `secretsdump` — dumps NTLM hashes as a domain admin,
- the BloodHound live-roast path,
- the LDAP RootDSE probe reading the real domain.

The DC is a **Samba AD DC** in Docker (`docker-compose.ad.yml`), self-provisioning the
`RECCE.LOCAL` domain; `provision-ad.sh` then adds a Kerberoastable service account.

## Gating

The test is inert by default. It runs **only** when `RECCE_AD_IT=1` **and** the DC is
reachable **and** the tools (`nxc`, `impacket-*`) are installed — otherwise it skips
cleanly, so it never affects the normal `pytest` run or a box without Docker.

## Run it locally

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

## CI

The `ad-integration` job in `.github/workflows/ci.yml` stands up the DC, provisions it,
and runs this test. It's marked `continue-on-error` until validated green on a real
runner, because Samba AD DC provisioning in CI is timing/DNS-sensitive and this scaffold
was authored without a local Docker to execute it against; flip that off once it's green.
