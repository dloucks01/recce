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

from bacpypes.app import BIPSimpleApplication
from bacpypes.core import run
from bacpypes.local.device import LocalDeviceObject
from bacpypes.object import AnalogValueObject, FileObject
from bacpypes.primitivedata import Real


DEVICE_ID = int(os.environ.get("BACNET_DEVICE_ID", "1234"))
BIND_ADDR = os.environ.get("BACNET_BIND", "0.0.0.0/24:47808")


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
