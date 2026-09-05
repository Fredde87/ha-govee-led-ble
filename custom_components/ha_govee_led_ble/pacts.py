"""Wire dialects ("pacts"), and which one a model speaks.

Govee devices do not share one protocol. They share an envelope -- 20 bytes, XOR checksum at
byte 19 -- and then each device family lays out the payload its own way. The vendor app models
this explicitly: every family is implemented by a *pact* package (`pact_tvlightv2`,
`pact_tvlightv4`, `h6104`, ...), the pact owns the byte layout, and the app picks the pact for a
device from the goodsType/pactType/pactCode it learns at pairing. Two devices can send the same
opcode and mean different things, and the pact is what disambiguates.

A pact decides WHICH FIELDS EXIST, not merely where they sit. Three pacts build the same
`33 05` video write three different ways:

  * `h6104`'s VideoVm.C() builds `{0, 0, d(), e()}` -- FOUR bytes, game mode and saturation
    only. There is no picture preset, no sound effects, no softness on this family at all.
  * `pact_tvlightv2`'s SubModeVideo.getWriteBytes builds six, with a BOOLEAN in slot 1.
  * `pact_tvlightv4`'s VideoVm.O() builds six, with a picture-preset byte (`0x08 | index`)
    in slot 1.

So "supports video mode" is not one capability. Asking a h6104 for a picture preset is not a
setting it will ignore; it is a field its body has no room for. This is why `video_fields`
below is part of the pact and why the consistency test in tests/test_pacts.py refuses a profile
that claims a video capability its pact cannot express.

The H66A0 sends 0x08 in slot 1, which is how we know it is tvlightv4 and not tvlightv2 -- the
same discriminator the app itself relies on. Nothing about the SKU string tells you this.

Why this module exists rather than another boolean on ModelProfile: a flag like
`uses_h6199_video_body` answers "is this model the exception?", which stops working the moment
there are three layouts. A pact name answers "which layout does this model speak?", which keeps
working for the fourth and the tenth. Adding a device family should mean naming its pact here
and pointing its profile at it, not editing call sites.

Adding a family:
  1. Identify its pact from the APK -- find the class whose getWriteBytes/O() builds the body,
     and the Info4Detail.g0() that parses the reply, and check they agree slot for slot.
  2. Add a Pact below recording that evidence.
  3. Set `pact=` on the model's profile in const.py.
Only step 3 touches existing code.

The layout names below are deliberately strings rather than callables. The builders live in
protocol.py and are chosen there; this module is the registry of which dialect a device speaks,
so importing it stays free of protocol imports and cannot create a cycle.
"""

from __future__ import annotations

from dataclasses import dataclass

# Layout tokens for the video body. `None` means the family has no video mode at all, which is
# not the same as "video mode we have not decoded yet" -- use UNKNOWN for that, so a device we
# have not finished reversing never silently borrows another family's layout.
VIDEO_BODY_NONE = None
VIDEO_BODY_UNKNOWN = "unknown"
VIDEO_BODY_H6199 = "h6199"
VIDEO_BODY_TVLIGHT_V2 = "tvlightv2"
VIDEO_BODY_TVLIGHT_V4 = "tvlightv4"
VIDEO_BODY_H6104 = "h6104"

# Field names a video body can carry. A pact lists the subset it actually has room for.
VIDEO_FIELD_GAME_MODE = "game_mode"
VIDEO_FIELD_SATURATION = "saturation"
VIDEO_FIELD_FULL_SCREEN = "full_screen"
VIDEO_FIELD_PICTURE_PRESET = "picture_preset"
VIDEO_FIELD_SOUND_EFFECTS = "sound_effects"
VIDEO_FIELD_SOFTNESS = "sound_effects_softness"
VIDEO_FIELD_RESERVED = "reserved"


@dataclass(frozen=True)
class Pact:
    """One wire dialect, named after the vendor's own package where there is one."""

    name: str
    video_body: str | None = VIDEO_BODY_NONE
    # The video body's fields, by name. Empty when the pact has no video body. This is the
    # authority on what a family can be asked for; see supports_video_field().
    video_fields: frozenset[str] = frozenset()
    doc: str = ""

    def supports_video_field(self, field: str) -> bool:
        """Whether this pact's video body has room for `field`."""
        return field in self.video_fields


PACTS: dict[str, Pact] = {
    # The default for a model whose family we have not reversed. It claims no layouts, so a
    # capability flag alone can never route a write into a body we have not proven.
    "generic": Pact(
        name="generic",
        video_body=VIDEO_BODY_NONE,
        doc="Envelope only: 20 bytes, XOR at byte 19, no family-specific payload claimed.",
    ),
    "h6199": Pact(
        name="h6199",
        video_body=VIDEO_BODY_H6199,
        video_fields=frozenset(
            {
                VIDEO_FIELD_FULL_SCREEN,
                VIDEO_FIELD_GAME_MODE,
                VIDEO_FIELD_SATURATION,
                VIDEO_FIELD_SOUND_EFFECTS,
                VIDEO_FIELD_SOFTNESS,
            }
        ),
        doc=(
            "H6199 and relatives. Video body carries full_screen/game_mode/saturation/"
            "sound_effects/softness, with the picture profile inverted relative to the app's "
            "own list order (Game is 1, Movie is 0). Every field replayed from capture."
        ),
    ),
    "tvlightv4": Pact(
        name="tvlightv4",
        video_body=VIDEO_BODY_TVLIGHT_V4,
        video_fields=frozenset(
            {
                VIDEO_FIELD_GAME_MODE,
                VIDEO_FIELD_PICTURE_PRESET,
                VIDEO_FIELD_SATURATION,
                VIDEO_FIELD_SOUND_EFFECTS,
                VIDEO_FIELD_SOFTNESS,
                VIDEO_FIELD_RESERVED,
            }
        ),
        doc=(
            "com.govee.pact_tvlightv4. Video body is game_mode/picture_preset/saturation/"
            "sound_effects/reserved/sound_effects_softness. Relative brightness is NOT in this body; "
            "it is the separate 0xae command. Confirmed in both "
            "directions: VideoVm.O() builds {0, d(), b(), e(), f(), g(), i()} and "
            "Info4Detail.g0() parses byte[4]->o() byte[5]->q(), and g/o share field f while "
            "i/q share field h. Distinguished from tvlightv2 by slot 1 being a preset byte "
            "rather than a boolean."
        ),
    ),
    # The two families below are recorded from the APK but have no device here to verify
    # against, so no profile points at them yet. They are present because the point of this
    # registry is that adding such a device is a data change, and because they are the evidence
    # that a video body is not one shape. Confirm against a capture before shipping either.
    "tvlightv2": Pact(
        name="tvlightv2",
        video_body=VIDEO_BODY_TVLIGHT_V2,
        video_fields=frozenset(
            {
                VIDEO_FIELD_FULL_SCREEN,
                VIDEO_FIELD_GAME_MODE,
                VIDEO_FIELD_SATURATION,
                VIDEO_FIELD_SOUND_EFFECTS,
                VIDEO_FIELD_SOFTNESS,
            }
        ),
        doc=(
            "com.govee.pact_tvlightv2. SubModeVideo.getWriteBytes builds six bytes with "
            "booleans in slots 0 and 1; parse() reads body[4]->voice and body[5]->g. UNVERIFIED "
            "against hardware."
        ),
    ),
    "h6104": Pact(
        name="h6104",
        video_body=VIDEO_BODY_H6104,
        video_fields=frozenset({VIDEO_FIELD_GAME_MODE, VIDEO_FIELD_SATURATION}),
        doc=(
            "com.govee.h6104. VideoVm.C() builds {0, 0, d(), e()} -- four bytes, game mode and "
            "saturation only. UNVERIFIED against hardware."
        ),
    ),
}


def get_pact(name: str) -> Pact:
    """Return a pact by name, falling back to the generic envelope.

    Falling back rather than raising is deliberate: an unknown pact name must degrade to
    claiming no layouts, never to guessing one.
    """
    return PACTS.get(name, PACTS["generic"])
