# RDP target — xrdp on :3389 with NLA DISABLED so the initial X.224
# Connection Request is accepted with security_layer=Standard RDP.
#
# Exercises recce.services.rdp:
#   * rdp_no_nla         (HIGH)   — Standard RDP security accepted
#   * rdp_fingerprint    (info)   — negotiated security layer captured
# BlueKeep-candidate and CredSSP paths need a Windows box to fire (this
# is Linux xrdp) — those stay covered by the win-sim placeholder + the
# vagrant AD DC.
#
# xrdp needs no desktop for the pre-auth X.224/RDP-Neg handshake; we
# skip the session backend entirely and let xrdp answer the negotiate
# and drop the connection when the client tries to open a session. The
# recce probe never gets that far — it only reads the CC/RDPNEG bytes.
FROM debian:12-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        xrdp \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt \
    && sed -ri 's|^security_layer=.*|security_layer=rdp|' /etc/xrdp/xrdp.ini \
    && sed -ri 's|^crypt_level=.*|crypt_level=low|' /etc/xrdp/xrdp.ini \
    && sed -ri 's|^tls_ciphers=.*|tls_ciphers=HIGH|' /etc/xrdp/xrdp.ini

# xrdp expects its private key to exist; the package's postinst usually
# generates one, but the slim install can race — create it once here.
RUN test -f /etc/xrdp/key.pem \
    || openssl req -x509 -nodes -newkey rsa:2048 \
         -subj "/CN=recce-lab-xrdp" \
         -keyout /etc/xrdp/key.pem -out /etc/xrdp/cert.pem -days 3650 \
    && chmod 600 /etc/xrdp/key.pem

EXPOSE 3389/tcp
# --nodaemon keeps xrdp in the foreground; docker supervises PID 1
# directly. sesman is not needed for the pre-auth fingerprint that
# recce.services.rdp reads — but xrdp refuses to boot without it, so
# spawn it in the background before xrdp takes over PID 1.
CMD ["/bin/sh", "-c", "xrdp-sesman --nodaemon & exec xrdp --nodaemon"]
