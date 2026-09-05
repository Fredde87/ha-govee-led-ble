"""The pact registry, and the profile/pact agreement it exists to enforce.

A pact is the wire dialect a model speaks (see pacts.py). These tests are less about the
registry's current contents than about the invariant that keeps it useful as devices are added:
a model's declared capabilities and its pact's actual byte layout must not be able to disagree.
"""

import pytest

from custom_components.ha_govee_led_ble.const import MODEL_PROFILES
from custom_components.ha_govee_led_ble.pacts import (
    PACTS,
    VIDEO_FIELD_SOUND_EFFECTS,
    Pact,
    get_pact,
)


def test_every_profile_names_a_pact_that_exists():
    """A typo in a pact name must not silently degrade a device to the generic envelope."""
    for model, profile in MODEL_PROFILES.items():
        assert profile.pact in PACTS, f"{model} names unknown pact {profile.pact!r}"


def test_unknown_pact_falls_back_to_claiming_nothing():
    fallback = get_pact("no-such-pact")
    assert fallback is PACTS["generic"]
    assert fallback.video_body is None
    assert fallback.video_fields == frozenset()


@pytest.mark.parametrize("model", sorted(MODEL_PROFILES))
def test_video_capability_matches_what_the_pact_can_express(model):
    """The invariant this module exists for.

    h6104's video body is four bytes carrying game mode and saturation, and nothing else. A
    profile that paired that pact with supports_video_sound_effects would be describing a field
    the body has no room for -- not a setting the device ignores. Catch it here rather than on
    the wire.
    """
    profile = MODEL_PROFILES[model]
    pact = get_pact(profile.pact)
    if profile.supports_video_mode:
        assert pact.video_body is not None, f"{model} claims video mode but pact {pact.name!r} declares no video body"
    if profile.supports_video_sound_effects:
        assert pact.supports_video_field(VIDEO_FIELD_SOUND_EFFECTS), (
            f"{model} claims video sound effects but pact {pact.name!r} has no such field"
        )


def test_the_two_six_byte_video_pacts_are_not_interchangeable():
    """tvlightv2 and tvlightv4 both build six bytes and still disagree about slot 1.

    This is the discriminator the H66A0 was identified by: it sends 0x08 there, which is a
    picture preset and not a boolean. If these two ever compare equal, that identification has
    lost its meaning.
    """
    v2, v4 = PACTS["tvlightv2"], PACTS["tvlightv4"]
    assert v2.video_fields != v4.video_fields
    assert v4.supports_video_field("picture_preset")
    assert not v2.supports_video_field("picture_preset")


def test_a_pact_with_no_video_body_claims_no_video_fields():
    for name, pact in PACTS.items():
        if pact.video_body is None:
            assert pact.video_fields == frozenset(), f"{name} claims fields with no body"
        else:
            assert pact.video_fields, f"{name} declares a body but names no fields"


def test_pact_is_frozen():
    """Profiles hold pacts by name; a mutable pact would let one device edit another's layout."""
    with pytest.raises(AttributeError):
        Pact(name="x").name = "y"
