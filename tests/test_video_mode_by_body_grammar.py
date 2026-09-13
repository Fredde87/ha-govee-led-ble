"""Every model that advertises video modes must be able to enter one.

`build_video_mode` only builds the H6199 body and raises "no generated video-mode grammar"
for anything else -- so the H66A0, whose effect list advertises "Video: Movie" and
"Video: Game", could not enter either.  The H66A0 body has its own builder
(`build_video_mode_h66a0`) and its own coordinator path (`async_enter_video_mode`, which
`set_video_settings` already used); the light entity's effect path just never routed there.

Observed on hardware with the camera module attached: selecting Video: Movie raised
"The device command failed" before any frame was confirmed.
"""

from __future__ import annotations

import pytest

from custom_components.ha_govee_led_ble.const import MODEL_PROFILES, get_profile
from custom_components.ha_govee_led_ble.generated_protocol_adapter import (
    build_video_mode,
    build_video_mode_h66a0,
)


@pytest.mark.parametrize("model", sorted(MODEL_PROFILES))
def test_a_model_that_advertises_video_modes_can_build_one(model: str) -> None:
    profile = get_profile(model)
    if not profile.video_modes:
        pytest.skip(f"{model} advertises no video modes")
    for mode in profile.video_modes:
        if profile.uses_h6199_video_body:
            packet = build_video_mode(mode, True, 100, False, 100, model)
        else:
            packet = build_video_mode_h66a0(
                game_mode=mode == "game",
                picture_preset="vivid",
                saturation=100,
                sound_effects=False,
                sound_effects_softness=100,
            )
        assert isinstance(packet, bytes) and packet, f"{model}/{mode} built nothing"
        assert packet[0] == 0x33, f"{model}/{mode} is not a command frame"
