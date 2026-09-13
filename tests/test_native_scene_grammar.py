"""A native scene must build for every model whose profile declares an effect grammar.

`build_native_scene_packets` keyed its activation frame on `protocol_model`, which returns the
SKU.  Only literal H617A and H6199 devices matched, so every model added since -- all of which
speak the H617A effect grammar behind their own SKU -- raised "no native-scene grammar" and
could not apply any of the scenes the entity advertised.  Reproduced on hardware: the H66A0
listed 174 effects and all of them failed with "The device command failed".
"""

from __future__ import annotations

import pytest

from custom_components.ha_govee_led_ble.const import MODEL_PROFILES, get_profile
from custom_components.ha_govee_led_ble.native_scenes import build_native_scene_packets
from custom_components.ha_govee_led_ble.scenes import MODEL_SCENES


@pytest.mark.parametrize("model", sorted(MODEL_PROFILES))
def test_every_profile_with_an_effect_grammar_can_build_a_scene(model: str) -> None:
    if get_profile(model).effect_grammar is None:
        pytest.skip(f"{model} declares no effect grammar")
    scenes = MODEL_SCENES.get(model) or {}
    if not scenes:
        pytest.skip(f"{model} has no catalogue scenes")
    scene = next(iter(scenes.values()))
    packets = build_native_scene_packets(model, scene)
    assert packets, f"{model} built no packets"
    assert all(isinstance(p, bytes) for p in packets)
