# iec104-sim

Minimal IEC 60870-5-104 responder — APCI framing + TESTFR/STARTDT/STOPDT
U-format acks + a two-frame General Interrogation reply (ActCon / ActTerm).

* Protocol: IEC-104 on 2404/tcp
* Library: none — stdlib socketserver.
  `lib60870-python` and `c104` both need build-from-source C libraries;
  hand-rolling avoids that.
* Targeted by recce module: `recce/services/iec104.py`
* Non-default env vars:
  * `IEC104_PORT` (default 2404)
  * `IEC104_CAA` (default 1) — Common ASDU Address

Coverage: reachable + STARTDT + a single dummy interrogation record. TLS
(IEC 62351-3) is not offered; the probe's `tls_handshake` reports False.
