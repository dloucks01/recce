# SIP target — Kamailio 5.x with a minimal cfg that:
#   * answers OPTIONS with a 200 OK carrying a Server header (fires
#     recce.services.sip.sip_fingerprint via the vendor-normaliser),
#   * uses a private-range advertised address (fires the
#     sip_internal_ip_disclosure emission via the Contact header),
#   * challenges REGISTER with a Digest realm (readable via
#     WWW-Authenticate).
FROM debian:12-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        kamailio \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt

COPY kamailio.cfg /etc/kamailio/kamailio.cfg

EXPOSE 5060/tcp 5060/udp
# `-DD` keeps kamailio in the foreground, `-E` logs to stderr so
# `docker logs` sees the startup banner. Fixed listen addresses so the
# advertised Contact host is the private-range lab IP.
CMD ["kamailio", "-DD", "-E", "-f", "/etc/kamailio/kamailio.cfg", \
     "-l", "udp:0.0.0.0:5060", "-l", "tcp:0.0.0.0:5060"]
