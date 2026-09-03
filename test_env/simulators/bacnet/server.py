"""Minimal BACnet/IP device — answers Who-Is with I-Am and exposes a Device
object + one Analog-Value + one File object so recce's bacnet probe returns
a valid detection (Who-Is, ReadProperty vendor/model/firmware/object-list,
WriteProperty dry-run against the AV). Not a full-fidelity implementation
— just enough wire behaviour to satisfy the probe.

Library: bacpypes 0.18.7 (BSD-2-Clause). Uses BIPSimpleApplication +
LocalDeviceObject, both of which handle Who-Is / I-Am and ReadProperty
without further wiring.
"""
from __future__ import annotations

import os
import socket

from bacpypes.app import BIPSimpleApplication
from bacpypes.core import run
from bacpypes.local.device import LocalDeviceObject
from bacpypes.object import AnalogValueObject, FileObject
from bacpypes.primitivedata import Real


DEVICE_ID = int(os.environ.get("BACNET_DEVICE_ID", "1234"))


def _resolve_bind_addr() -> str:
    """Compute a BACnet BIP bind address of the form `<own-ip>/24:47808`.

    bacpypes needs a concrete IP + mask so it can derive the broadcast
    address (BIP broadcasts I-Am on the /24's .255). Using
    `0.0.0.0/24:47808` — the naive "listen on any interface" idiom —
    tries to bind the broadcast to 0.0.0.255 and fails with Errno 99
    inside a container. Prefer the operator's override, else look up
    the container's own IP on the recce-testnet interface.
    """
    override = os.environ.get("BACNET_BIND")
    if override:
        return override
    # Container's own IP — hostname resolves to the compose-assigned
    # address (172.20.0.60 in the recce test env).
    try:
        own_ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        own_ip = "0.0.0.0"
    return f"{own_ip}/24:47808"


BIND_ADDR = _resolve_bind_addr()


def main() -> None:
    device = LocalDeviceObject(
        objectName="recce-sim",
        objectIdentifier=("device", DEVICE_ID),
        maxApduLengthAccepted=1476,
        segmentationSupported="segmentedBoth",
        vendorIdentifier=999,
        vendorName="Recce Lab",
        modelName="RecceSim-BAC-1",
        firmwareRevision="1.0.0",
        applicationSoftwareVersion="1.0.0",
        description="recce test env simulator",
    )
    app = BIPSimpleApplication(device, BIND_ADDR)

    av = AnalogValueObject(
        objectIdentifier=("analogValue", 1),
        objectName="AV-1",
        presentValue=Real(42.0),
        description="test AV — recce probe write-dry-run target",
    )
    app.add_object(av)

    fobj = FileObject(
        objectIdentifier=("file", 1),
        objectName="config.bin",
        description="recce test env stub file",
    )
    app.add_object(fobj)

    print(f"bacnet-sim: device instance {DEVICE_ID} listening on {BIND_ADDR}", flush=True)
    run()


if __name__ == "__main__":
    main()
