# IPMI target — Python UDP responder implementing just enough of the
# IPMI 1.5/2.0 wire protocol to exercise recce.services.ipmi's probes:
#
#   * Get Channel Auth Capabilities (cmd 0x38) — advertises
#     none|MD5|MD2|password auth types + anonymous + null-user logon +
#     IPMI 2.0 support → fires the T1 cipher_zero heuristic, null_user,
#     anonymous_login, and weak_auth findings.
#   * Get Device ID (cmd 0x01) — reports vendor=Dell (674) + firmware
#     1.20 → fires ipmi_device_id with the vendor label.
#   * Get Channel Cipher Suites (cmd 0x54) — returns a suite record
#     with auth_alg=0 → confirms cipher_zero (T1 upgrade).
#   * RMCP+ Open Session Request (payload type 0x10) — accepts the
#     auth_alg=0 negotiation → fires the T2 cipher_zero session
#     evidence.
#
# No real BMC state, no RAKP hash generation (recce reads what the BMC
# gives — a sim that never opens sessions leaves the RAKP-sweep path
# empty, which is exactly what a hardened BMC would do).
FROM python:3.11-slim

WORKDIR /app
COPY server.py /app/server.py

EXPOSE 623/udp
CMD ["python", "-u", "/app/server.py"]
