# s7-sim

Siemens S7 simulator via `python-snap7` + `libsnap7`. Binds 102/tcp with
COTP + S7COMM SetupCommunication and answers the common SZL queries.

* Protocol: ISO-TSAP / S7COMM on 102/tcp
* Library: `python-snap7==1.3` (MIT). Wraps `libsnap7` (LGPLv3) which the
  Dockerfile builds from the upstream Sourceforge 1.4.2 tarball —
  requires network access at `docker build` time.
* Targeted by recce module: `recce/services/s7.py`
* Non-default env vars:
  * `S7_PORT` (default 102 — informational; libsnap7 binds 102 internally)
  * `S7_RACK` / `S7_SLOT` (default 0 / 2 — S7-300/400 CPU location)

Coverage: COTP + Setup Communication + SZL 0x0011 (module id) +
0x001C (component id). SZL 0x0232 (protection level) is answered by
libsnap7 with protection=1 (no password). CVE-2016-9159 (SZL 0x0132)
is NOT reproduced — the probe's `legacy_password_readout` stays None.
