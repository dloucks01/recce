# dnp3-sim

Minimal DNP3 outstation over TCP — Data-Link REQUEST_LINK_STATUS +
FC1 Read of Class 0 (g60v1) enough to satisfy recce's `dnp3` probe.

* Protocol: DNP3 (IEEE 1815) on 20000/tcp
* Library: none — stdlib socketserver + hand-rolled CRC-16-DNP.
  `pydnp3` / `dnp3-python` wrap opendnp3 (Apache-2.0) but the wheels
  build from source (cmake + boost) which bloats the sim image.
* Targeted by recce module: `recce/services/dnp3.py`
* Non-default env vars:
  * `DNP3_PORT` (default 20000)
  * `DNP3_OUTSTATION_ADDR` (default 1024)

Coverage: link-status and Class 0 read only. IIN flags are cleared and
Group 0 device-attribute reads are not answered, so recce's
`vendor / product / firmware` fields stay empty — that is correct sim
behaviour (no CVE fingerprint on a lab device).
