"""DreamView group model: members, Area Config and the readers for the `0x60` register.

The vendor calls this "Feast" internally. A sync centre HOLDS a group of sub-devices and drives
them; membership and per-member Area Config are written as one `0xa3` upload and are never read
back, so a group deleted from here cannot be rebuilt from here.

Wire STRUCTURE lives in tools/ble/kaitai/command_write.ksy::dreamview_cmd and its builders in
generated_protocol_adapter. What is here is the group model that upload serialises, and the two
readers for registers whose replies are a digest rather than a modelled body.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from .generated_protocol_adapter import DreamviewReply, parse_dreamview_reply
from .transport import fragment_a3

# The `aa` status header, for the two 0x60 replies read here as raw bodies.
STATUS_HEADER = 0xAA

DREAMVIEW_PACKET_TYPE = 0x60
DREAMVIEW_SUB_SWITCH = 0x01
DREAMVIEW_SUB_DEVICE_BRIGHTNESS = 0x03
DREAMVIEW_SUB_BRIGHTNESS_UNITE = 0x04
DREAMVIEW_SUB_SUBDEVICE = 0x05
DREAMVIEW_SUB_SATURATION = 0x09
DREAMVIEW_SUB_GET_COLOR = 0x0A
DREAMVIEW_SUB_SOUND = 0x0B
DREAMVIEW_SUB_DIGEST = 0x0C

DREAMVIEW_GROUP_TYPE = 0x50  # MultiSetSubDeviceController4MovieFeastV2.getCommandType()

# `cmdVer` is a CLOUD field, and we have no cloud. Both sub-devices in the only capture of this
# command reported 11, so that is what this defaults to -- an observed value, not a derived one.
# It is exposed as a parameter so a device that disagrees can be corrected without a code change.
DREAMVIEW_DEFAULT_CMD_VER = 0x0B

# A zone whose switchConfig is off is written as 0xFF rather than omitted, so the zone count and
# the entry length stay fixed however many zones are disabled.
DREAMVIEW_ZONE_DISABLED = 0xFF

# Which screen region a zone samples. The app's Area Config page has TWENTY cells around the
# screen (the shrink/expand panel pair) and stores the picked cell as `Z + 1`, i.e. 1..20 -- but
# Constant.getIndex4Portocol folds 1..10 and 11..20 onto the SAME ten protocol regions before the
# byte reaches the wire, and returns 0 for anything else. So the wire only ever carries 0..10.
#
# 0 is UNASSIGNED, not "region zero": the app writes areaConfigs[i] = 0 together with
# switchConfigs[i] = 0 when a zone is cleared, and defaults a new device's areaConfigs to zeros.
DREAMVIEW_REGION_UNASSIGNED = 0
DREAMVIEW_REGION_MAX = 10


@dataclass(frozen=True)
class DreamviewMember:
    """One sub-device in a DreamView group, with its per-zone Area Config.

    `address` is the ordinary display form (`AA:BB:CC:DD:EE:FF`). It goes onto the wire
    REVERSED -- the APK reads it with BleUtil.address2Bytes, which preserves display order, then
    appends it from the last byte down to the first. Verified against real data: an entry from a
    captured group, reversed, matches a device address recovered independently from a different
    capture's handshake, while the unreversed form matches nothing.

    `zones` is one entry per zone, in zone order:

      * ``1..10`` -- the screen region that zone samples (the app's areaConfigs).
      * ``0``     -- assigned to no region. This is the app's own default for a new device.
      * ``None``  -- the zone is switched OFF (the app's switchConfigs), written as 0xFF.

    The app's Area Config page shows twenty cells, but folds them onto these ten before writing,
    so 1..10 is the whole range the wire ever carries.
    """

    address: str
    zones: tuple[int | None, ...]
    is_rgbic: bool = True
    cmd_ver: int = DREAMVIEW_DEFAULT_CMD_VER

    def __post_init__(self) -> None:
        if not _MAC_RE.fullmatch(self.address):
            raise ValueError(f"address must be AA:BB:CC:DD:EE:FF, got {self.address!r}")
        if not 1 <= len(self.zones) <= 255:
            raise ValueError(f"a member needs 1..255 zones, got {len(self.zones)}")
        for zone in self.zones:
            if zone is None:
                continue
            if not DREAMVIEW_REGION_UNASSIGNED <= zone <= DREAMVIEW_REGION_MAX:
                raise ValueError(
                    f"zone region must be 0..{DREAMVIEW_REGION_MAX} (0 = unassigned) or None to "
                    f"disable the zone, got {zone}"
                )
        if not 0 <= self.cmd_ver <= 0xFF:
            raise ValueError(f"cmd_ver must be a byte, got {self.cmd_ver}")

    def to_bytes(self) -> bytes:
        """Encode one Area4Device.j() entry."""
        mac = bytes(int(part, 16) for part in self.address.split(":"))
        return bytes(
            [
                1 if self.is_rgbic else 0,
                0,  # the app's marker bit: 0 when a BLE address is present, 1 when it sends a name
                self.cmd_ver,
                *reversed(mac),
                len(self.zones),
                *(DREAMVIEW_ZONE_DISABLED if z is None else z for z in self.zones),
            ]
        )


@dataclass(frozen=True)
class DreamviewState:
    """What a sync centre will tell us about its own DreamView group.

    Assembled from two reads, because no single one answers everything:

      * `aa 60 0c` -- a digest of the group's SETTINGS in one frame.
      * `aa 60 05` -- one byte per sub-device SLOT, its connection state.

    Same-brightness is deliberately absent: it has its own read, `aa 60 04`, and the digest byte
    that looked like it demonstrably is not (see parse_dreamview_digest).

    `member_states` is the honest limit of this. The device reports a state per slot but never
    the addresses behind them: the vendor app knows who is in the group because its CLOUD
    account told it, and indexes these bytes against that list. So we can say how many
    sub-devices a group holds and whether each is connected, and we cannot say which devices
    they are. A group created in the app is therefore VISIBLE to us but not enumerable.
    """

    is_on: bool | None = None
    brightness: int | None = None
    saturation: int | None = None
    sound_effects: bool | None = None
    # The 0x0a "get colour mode" selector -- the app's All/Part choice. Reported as the raw byte
    # because only the values 0 and 1 have been observed and neither has been tied to a label.
    colour_mode: int | None = None
    sound_effects_softness: int | None = None
    member_states: tuple[int, ...] = ()

    @property
    def member_count(self) -> int:
        """How many sub-device slots report a non-zero state."""
        return sum(1 for state in self.member_states if state)

    @property
    def has_group(self) -> bool:
        """Whether any sub-device is currently connected -- NOT whether a group exists.

        The distinction became real once `33 60 05` was identified: a member can be
        DISCONNECTED from the sync centre (state 0) while remaining a member, with its Area
        Config and brightness intact. A group whose members are all disconnected therefore
        reports False here even though deleting it would still destroy something.

        So treat True as proof a group exists and False as "no member is connected right now".
        `aa 60 03` is the second signal -- its length tracked membership across a delete in the
        2026-08-27 live run -- and is the read to reach for before concluding a group is absent.
        """
        return self.member_count > 0


def parse_dreamview_digest(frame: bytes) -> DreamviewState:
    """Parse `aa 60 0c`, the group's settings in one frame.

    Field order and the unnamed byte are documented on `digest_body` in
    `tools/ble/kaitai/dreamview_reply.ksy`, where the structure now lives.
    """
    parsed = parse_dreamview_reply(frame)
    if parsed.sub != DreamviewReply.DreamviewSub.digest:
        raise ValueError(f"expected DreamView sub 0x{DREAMVIEW_SUB_DIGEST:02x}, got 0x{int(parsed.sub.value):02x}")
    body = parsed.body
    return DreamviewState(
        is_on=bool(body.is_on),
        brightness=body.brightness,
        saturation=body.saturation,
        sound_effects=bool(body.sound_effects),
        colour_mode=body.colour_mode,
        sound_effects_softness=body.sound_effects_softness,
    )


def parse_dreamview_members(frame: bytes) -> tuple[int, ...]:
    """Parse `aa 60 05` into one connection state per sub-device slot.

    Ten slots, matching the app's own maximum.  Trailing zero slots are kept rather than
    trimmed, so the index of a state is the index of its sub-device.
    """
    parsed = parse_dreamview_reply(frame)
    if parsed.sub != DreamviewReply.DreamviewSub.subdevice:
        raise ValueError(f"expected DreamView sub 0x{DREAMVIEW_SUB_SUBDEVICE:02x}, got 0x{int(parsed.sub.value):02x}")
    return tuple(parsed.body.slots)


def build_dreamview_group(members: Sequence[DreamviewMember]) -> list[bytes]:
    """Build the `0xa3` upload that sets a DreamView group's membership and Area Config.

    THIS IS NOT READ-BACKABLE. No query returns group membership, so this write cannot be
    verified against the device afterwards and a previous group cannot be recovered from it.

    An empty `members` is rejected rather than treated as "remove everyone": the app's own
    makeSubDeviceBytes returns null for an empty list, so an empty upload is not a form the
    firmware has been shown to accept. Use build_dreamview_delete for removal.
    """
    if not members:
        raise ValueError("a DreamView group needs at least one member; use build_dreamview_delete to remove one")
    if len(members) > 10:
        # The app's Constant.maxSubDeviceNum caps this per model at 5, 7 or 10 by cloud lookup.
        # 10 is the largest of those, so it is the only bound we can enforce without the cloud.
        raise ValueError(f"at most 10 sub-devices, got {len(members)}")
    seen: set[str] = set()
    for member in members:
        key = member.address.upper()
        if key in seen:
            raise ValueError(f"{member.address} appears twice in the group")
        seen.add(key)
    body = bytes([len(members)]) + b"".join(member.to_bytes() for member in members)
    return fragment_a3(DREAMVIEW_GROUP_TYPE, body)


_MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}")
