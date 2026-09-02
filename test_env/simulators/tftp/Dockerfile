# TFTP target — tftpd-hpa on :69/udp with a seeded /srv/tftp tree.
#
# The seeded files are deliberately named to match recce.services.tftp's
# canonical hit list — a bogus IOS running-config (matches
# tftp_readable's critical-severity heuristic) and a bare test.txt that
# fires the medium-severity variant. The running-config content is
# lab-only mock data (no real hostnames, no real secrets).
FROM debian:12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends tftpd-hpa \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt

RUN mkdir -p /srv/tftp && chown -R nobody:nogroup /srv/tftp
COPY root/ /srv/tftp/
RUN chown -R nobody:nogroup /srv/tftp && chmod -R 0644 /srv/tftp/*

# tftpd-hpa in foreground (`-L` = log to stdout so `docker logs` works).
# `--secure` chroots to the -s directory (defence in depth on the lab,
# not a security posture — the whole tree is intentionally readable).
EXPOSE 69/udp
CMD ["/usr/sbin/in.tftpd", \
     "--foreground", "--verbose", \
     "--listen", "--address", "0.0.0.0:69", \
     "--secure", "/srv/tftp"]
