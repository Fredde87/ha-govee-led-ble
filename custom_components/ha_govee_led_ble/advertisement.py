"""What a Govee BLE advertisement says about a device before anything connects to it.

The manufacturer id is not a Bluetooth SIG company: Govee packs its own flags byte into the low
half, so 0x8843 decodes as flags 0x43 -- broadcast protocol version 3 in bits 0-3, and bit 6 set,
which is the app's "device supports encryption" bit (BleUtil.parseBleBroadcastPact) -- followed
by the literal 0x88 0xEC magic, then pactType and pactCode.

Cross-checked against the device rather than read off the APK alone: `aa ef` on an H66A0 answers
the same pactType and pactCode this advertisement carries.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

# 0x88 0xEC, Govee's literal magic, sitting in the high byte of the manufacturer id and the
# first payload byte.
_GOVEE_ADVERTISEMENT_MAGIC = b"\x88\xec"
# flags + magic + pactType(u16 big-endian) + pactCode.
_GOVEE_ADVERTISEMENT_LENGTH = 6
# BleUtil.parseBleBroadcastPact's "device supports encryption" bit.
ADVERTISEMENT_ENCRYPTION_BIT = 0x40


@dataclass(frozen=True, slots=True)
class GoveeAdvertisement:
    """Capability keys a Govee device broadcasts, readable without connecting."""

    pact_type: int
    pact_code: int
    broadcast_version: int
    supports_encryption: bool


def parse_govee_advertisement(
    manufacturer_data: Mapping[int, bytes],
) -> GoveeAdvertisement | None:
    """Read pactType/pactCode out of a Govee advertisement, or None if it is not one."""
    for company_id, payload in manufacturer_data.items():
        if not 0 <= company_id <= 0xFFFF:
            continue
        wire = company_id.to_bytes(2, "little") + bytes(payload)
        if len(wire) < _GOVEE_ADVERTISEMENT_LENGTH or wire[1:3] != _GOVEE_ADVERTISEMENT_MAGIC:
            continue
        return GoveeAdvertisement(
            pact_type=int.from_bytes(wire[3:5], "big"),
            pact_code=wire[5],
            broadcast_version=wire[0] & 0x0F,
            supports_encryption=bool(wire[0] & ADVERTISEMENT_ENCRYPTION_BIT),
        )
    return None
