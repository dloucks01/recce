#!/usr/bin/env bash
# Provision the running Samba AD DC (docker-compose.ad.yml) with a KERBEROASTABLE service
# account, so the credentialed-AD integration test has something to roast.
#
# Idempotent: safe to re-run. Waits for the DC to finish provisioning first.
set -euo pipefail

CID="${RECCE_AD_CONTAINER:-recce-ad-dc}"
SPN_USER="${RECCE_AD_SPN_USER:-svc_sql}"
SPN_PASS="${RECCE_AD_SPN_PASS:-Sql!Passw0rd}"
SPN="${RECCE_AD_SPN:-MSSQLSvc/db.recce.local:1433}"

echo "[*] Waiting for the DC ($CID) to finish provisioning ..."
for i in $(seq 1 60); do
  if docker exec "$CID" samba-tool domain info 127.0.0.1 >/dev/null 2>&1; then
    echo "[+] DC is up."
    break
  fi
  sleep 5
  if [ "$i" = 60 ]; then
    echo "[x] DC did not come up in time." >&2
    docker logs --tail 50 "$CID" >&2 || true
    exit 1
  fi
done

echo "[*] Creating Kerberoastable service account '$SPN_USER' ..."
docker exec "$CID" samba-tool user create "$SPN_USER" "$SPN_PASS" \
  --description "recce integration: kerberoastable service account" 2>/dev/null \
  || echo "    (user already exists - continuing)"

echo "[*] Registering SPN '$SPN' on '$SPN_USER' ..."
docker exec "$CID" samba-tool spn add "$SPN" "$SPN_USER" 2>/dev/null \
  || echo "    (SPN already present - continuing)"

echo "[+] Provisioning complete: $SPN_USER is Kerberoastable via $SPN."

# `samba-tool domain info` only proves the DC answers ITSELF, from inside the
# container. Samba restarts its services around provisioning, so the published
# ports can still flap for a moment afterwards - on a GitHub runner that raced
# the test suite and recce's LDAP probe got a connection error (the probe
# returns None on OSError, which read as "LDAP returned nothing").
#
# Gate on the DC answering from the HOST, and require several CONSECUTIVE clean
# rounds so a momentary window during a service restart can't look like ready.
echo "[*] Waiting for 445/389/88 to answer from the host ..."
need=3
streak=0
for i in $(seq 1 90); do
  ok=1
  for p in 445 389 88; do
    (exec 3<>/dev/tcp/127.0.0.1/"$p") 2>/dev/null && exec 3<&- || ok=0
  done
  if [ "$ok" = 1 ]; then
    streak=$((streak + 1))
    [ "$streak" -ge "$need" ] && { echo "[+] DC is serving on the host ($need consecutive checks)."; exit 0; }
  else
    streak=0
  fi
  sleep 2
done
echo "[x] DC never answered steadily on 445/389/88 from the host." >&2
docker logs --tail 50 "$CID" >&2 || true
exit 1
