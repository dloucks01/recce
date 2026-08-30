# bacnet-sim

Minimal BACnet/IP device — Who-Is / I-Am + one AnalogValue + one File object.

* Protocol: BACnet/IP (ASHRAE 135) on 47808/udp
* Library: `bacpypes==0.18.7` (BSD-2-Clause)
* Targeted by recce module: `recce/services/bacnet.py`
* Non-default env vars:
  * `BACNET_DEVICE_ID` (default 1234) — Device object instance
  * `BACNET_BIND` (default `0.0.0.0/24:47808`) — bacpypes address spec

Not a full-fidelity controller — BBMD, Foreign-Device registration, DCC and
Reinitialize are handled by bacpypes' defaults (usually rejected), so the
probe's write / DCC / reinit sub-checks report "not accepted" rather than
"critical". That is the correct answer for a sim.
