# enip-sim

Minimal EtherNet/IP (ODVA CIP) encapsulation responder — List Identity,
List Services, List Interfaces, RegisterSession/UnregisterSession.

* Protocol: EtherNet/IP on 44818/tcp
* Library: none — stdlib socketserver.
  `cpppo` (`python -m cpppo.server.enip`) would give a fuller CIP object
  tree but is GPLv3, which would attach to a redistributed image.
* Targeted by recce module: `recce/services/enip.py`
* Non-default env vars:
  * `ENIP_PORT` (default 44818)
  * `ENIP_VENDOR_ID` (default 999)
  * `ENIP_SERIAL` (default `0xDEADBEEF`)
  * `ENIP_PRODUCT_NAME` (default `RecceSim-ENIP-1`)

Coverage: connectionless identity/services + RegisterSession. CIP MR
GetAttributesAll on Identity / TCP/IP / Ethernet Link objects returns
"status: invalid command" so the probe's `tcpip`, `ethlink`,
`identity_detailed` fields stay empty — correct sim behaviour.
