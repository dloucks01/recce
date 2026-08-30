"""Siemens S7 simulator — python-snap7 Server (a Python binding around the
libsnap7 C library, which ships a working S7 server implementation).

Recce's `s7` probe walks COTP → SetupCommunication → SZL 0x0011 / 0x001C /
0x0232 / 0x0131 / 0x0132, and snap7.Server answers SetupCommunication +
the common SZL IDs (module id, component id, protection level) natively.
That covers the s7_stack / order_code / firmware / put_get_enabled fields
of the probe.

python-snap7 is MIT. libsnap7.so is LGPLv3 and must be present at runtime
(the Dockerfile builds it from Sourceforge).
"""
from __future__ import annotations

import ctypes
import os
import time

import snap7
from snap7 import snap7types


PORT = int(os.environ.get("S7_PORT", "102"))
RACK = int(os.environ.get("S7_RACK", "0"))
SLOT = int(os.environ.get("S7_SLOT", "2"))


def main() -> None:
    srv = snap7.server.Server()
    # Pre-register a couple of data areas so the probe's block-list /
    # read-var checks return non-empty responses instead of "area not
    # found". 100-byte scratch DBs are the classic S7-300 default.
    for db_num in (1, 2, 3):
        buf = (ctypes.c_uint8 * 100)()
        srv.register_area(snap7types.srvAreaDB, db_num, buf)

    srv.start_to("0.0.0.0")
    print(f"s7-sim: snap7.Server rack {RACK} slot {SLOT} bound on 0.0.0.0:{PORT} "
          f"(libsnap7 default)", flush=True)
    try:
        while True:
            time.sleep(3600)
    finally:
        srv.stop()
        srv.destroy()


if __name__ == "__main__":
    main()
