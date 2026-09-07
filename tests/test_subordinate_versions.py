"""The `aa 20` / `aa 21` registers carry version strings on the H617A grammars too.

Only the H6199 grammar mapped these to `version_body`; the H617A and H66A0 roots left the
body as raw bytes, so the reader's `generated.body.text` raised AttributeError.  The handler
does not catch AttributeError, so the failure escaped into the BLE notify callback and took
the rest of the frame's handling with it -- including the `_probe_other_replies` counter the
camera-presence verdict depends on.

Frames below are the bytes the H61F5 and H66A0 actually sent, taken from the coordinator's
own packet log on hardware.
"""

from __future__ import annotations

import pytest

from custom_components.ha_govee_led_ble.coordinator_status import decode_status_frame_result

SUBORDINATE_20 = bytes.fromhex("aa20312e30342e303200000000000000000000bd")
SUBORDINATE_21 = bytes.fromhex("aa21312e30332e303800000000000000000000b1")


@pytest.mark.parametrize("model", ["H617A", "H61F5", "H1A42", "H66A0", "H6199"])
@pytest.mark.parametrize(
    ("frame", "expected"),
    [(SUBORDINATE_20, "1.04.02"), (SUBORDINATE_21, "1.03.08")],
)
def test_subordinate_registers_decode_as_version_text(model: str, frame: bytes, expected: str) -> None:
    parsed = decode_status_frame_result(frame, model).parsed
    assert parsed is not None, f"{model} failed to parse {frame.hex()}"
    assert parsed.generated.body.text == expected
