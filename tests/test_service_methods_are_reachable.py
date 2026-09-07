"""Every registered service must resolve to a method the entity actually has.

Registration does not check this: `async_register_entity_service` takes the method name as a
string, so a mixin that is never placed in the MRO registers cleanly and then raises
AttributeError on the first call.  That is exactly what happened to the video and DreamView
services -- twelve of them were registered against methods no entity carried, and the unit
tests missed it because they exercised the mixin directly rather than through the entity.
"""

from __future__ import annotations

from custom_components.ha_govee_led_ble.light import GoveeBLELight
from custom_components.ha_govee_led_ble.light_services_registration import _ENTITY_SERVICES


def test_every_registered_service_resolves_to_an_entity_method() -> None:
    missing = [
        (service, method) for service, _schema, method, *_rest in _ENTITY_SERVICES if not hasattr(GoveeBLELight, method)
    ]
    assert not missing, f"registered services with no method on the entity: {missing}"


def test_the_dreamview_and_video_surface_is_on_the_entity() -> None:
    """Named explicitly so a mixin dropped out of the MRO fails loudly rather than silently."""
    for method in (
        "async_set_video_settings",
        "async_set_video_blank_screen",
        "async_get_dreamview_candidates",
        "async_read_dreamview_group",
        "async_identify_dreamview_members",
        "async_set_dreamview_group",
        "async_set_dreamview_switch",
        "async_set_dreamview_member_brightness",
        "async_set_dreamview_same_brightness",
        "async_set_dreamview_sound_effects",
        "async_delete_dreamview_group",
        "async_release_ble",
    ):
        assert hasattr(GoveeBLELight, method), f"{method} is not reachable on GoveeBLELight"
