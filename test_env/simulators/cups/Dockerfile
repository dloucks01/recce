# CUPS / IPP target — port :631 answering IPP Get-Printer-Attributes on
# a lab-only PDF printer. Exercises recce.services.ipp:
#   * ipp_cups        — CUPS Server header fingerprint
#   * ipp_printers    — the printer list returned by CUPS-Get-Printers
#   * ipp_cups_patched (or the CVE-2024-47176 marker when unpatched)
#
# Debian-slim + cups-daemon + cups-pdf gives us a single PDF-loopback
# queue with zero real hardware. Deliberately listens on 0.0.0.0 with
# the admin UI reachable (again, LAB ONLY).
FROM debian:12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cups cups-pdf cups-client cups-filters cups-bsd \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt

COPY cupsd.conf /etc/cups/cupsd.conf
COPY start.sh /start.sh
RUN chmod +x /start.sh \
    && mkdir -p /var/spool/cups-pdf/ANONYMOUS \
    && chown -R lp:lp /var/spool/cups-pdf

EXPOSE 631/tcp
CMD ["/start.sh"]
