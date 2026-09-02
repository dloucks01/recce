#!/bin/sh
# Bring up cupsd in the foreground with a single lab-only PDF loopback
# queue so recce.services.ipp.ipp_printers has something to enumerate.
set -eu

# Foreground cupsd so docker can supervise it. `-l` = launched-by-inet-
# style logging, `-f` = do not fork.
cupsd -f &
CUPS_PID=$!

# Poll the socket until cupsd is ready — lpadmin can't talk to a dead
# scheduler, and the first fork takes ~1s inside a container.
for i in 1 2 3 4 5 6 7 8 9 10; do
    if lpstat -r >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Add a single PDF loopback printer. Idempotent (script runs on every
# container start; lpadmin -p is a create-or-update). `-P <ppd>` (upper
# case) is the direct-PPD form and still works on CUPS 2.4 even after
# `-m <model>` (cups-driverd path) was deprecated.
lpadmin -p RecceLabPDF \
    -v cups-pdf:/ \
    -P /usr/share/ppd/cups-pdf/CUPS-PDF_opt.ppd \
    -E \
    -D "recce-lab PDF loopback printer" \
    -L "recce test env" \
    2>/dev/null || true
cupsaccept RecceLabPDF 2>/dev/null || true
cupsenable RecceLabPDF 2>/dev/null || true

# Hand control back to cupsd.
wait "$CUPS_PID"
