"""Invariants that hold a profile's declarations against the wire grammar it routes to.

Every check here exists because the suite once passed while the thing it checks was broken.
A profile can declare a capability the grammar cannot express, and nothing fails until a real
device answers: the reply parses as raw bytes, a reader reaches for a field, and the exception
lands inside the BLE notification callback where it is swallowed. These tests do on every
profile what only hardware used to do.
"""

import re
from pathlib import Path

import pytest

from custom_components.ha_govee_led_ble.const import MODEL_PROFILES, ReadDomain
from custom_components.ha_govee_led_ble.coordinator_status import _STATUS_DOMAIN_NAMES

_KAITAI = Path(__file__).resolve().parent.parent / "tools" / "ble" / "kaitai"
_STATUS_ROOT_FILES = {
    "H617A": "status_reply.ksy",
    "H6099": "speculative/h6099_status_reply.ksy",
    "H6199": "h6199_status_reply.ksy",
    "H66A0": "speculative/h66a0_status_reply.ksy",
    "H6102": "speculative/h6102_status_reply.ksy",
}
# Domains no status reply carries: they are answered by a different frame family entirely.
_NOT_STATUS_REPLY_DOMAINS = {ReadDomain.INSTALLATION_DIRECTION, ReadDomain.CAMERA_HEALTH}


_CASE = re.compile(r"^\s+'[a-z0-9_]+::([a-z0-9_]+)'\s*:")


def _typed_cases(grammar: str) -> set[str]:
    """Reply-domain names this root gives a typed body, rather than leaving as raw bytes.

    Read straight out of the schema text rather than through a YAML parser, to keep this
    check from adding a dependency the project does not otherwise carry.
    """
    path = _KAITAI / _STATUS_ROOT_FILES[grammar]
    assert path.is_file(), f"no status root file mapped for grammar {grammar}"
    cases: set[str] = set()
    inside = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() == "cases:":
            inside = True
            continue
        if inside:
            match = _CASE.match(line)
            if match:
                cases.add(match.group(1))
            elif line.strip() and not line.startswith(" " * 8):
                inside = False
    assert cases, f"{grammar} root has no switch cases"
    return cases


_PROFILES_WITH_STATUS = sorted(name for name, profile in MODEL_PROFILES.items() if profile.status_grammar is not None)


@pytest.mark.parametrize("model", _PROFILES_WITH_STATUS)
def test_every_claimed_read_domain_has_a_typed_body(model: str) -> None:
    """A claimed domain whose body falls through to raw bytes is the `.text`/`.value` bug:
    the reply parses, the reader reaches for a field, and AttributeError is raised inside the
    notification callback, losing the notification rather than degrading."""
    profile = MODEL_PROFILES[model]
    typed = _typed_cases(profile.status_grammar)
    reply_names: dict[ReadDomain, set[str]] = {}
    for name, domain in _STATUS_DOMAIN_NAMES.items():
        reply_names.setdefault(domain, set()).add(name)
    missing = sorted(
        domain.value
        for domain in profile.read_domains
        if domain not in _NOT_STATUS_REPLY_DOMAINS and domain in reply_names and not (reply_names[domain] & typed)
    )
    assert not missing, f"{model} claims {missing} but its {profile.status_grammar} root leaves them raw"


def _xor(frame: bytes) -> bytes:
    checksum = 0
    for byte in frame:
        checksum ^= byte
    return frame + bytes([checksum])


def _segment_pages(profile) -> list[bytes]:
    """The pages this device would send: a full record area every time, meaningful records
    first and the slots the strip does not have zero-filled, which is what hardware does."""
    pages = []
    for group in range(1, profile.segment_group_count + 1):
        offset = (group - 1) * profile.segment_group_size
        meaningful = min(profile.segment_group_size, profile.segment_count - offset)
        records = b""
        for index in range(profile.segment_group_size):
            segment = offset + index
            records += bytes([50 + segment, segment + 1, 0, 0]) if index < meaningful else bytes(4)
        body = bytes([group]) + records
        pages.append(_xor(bytes([0xAA, 0xA5]) + body.ljust(17, b"\x00")))
    return pages


_SEGMENT_MODELS = sorted(
    name
    for name, profile in MODEL_PROFILES.items()
    if profile.supports_segments and profile.can_read(ReadDomain.SEGMENTS) and profile.status_grammar
)


@pytest.mark.parametrize("model", _SEGMENT_MODELS)
def test_declared_segment_paging_matches_the_grammar_it_reads_through(model: str) -> None:
    """A profile can declare a page shape its status root does not read, and nothing fails
    until a device answers: the pages are discarded, segment state never leaves "optimistic",
    and every segment service then reports failure after the write has already applied.

    Checked against the declared profile rather than a coordinator's, because a runtime
    profile may still be waiting on capability resolution while the declaration is what a
    reviewer reads.
    """
    from custom_components.ha_govee_led_ble.generated_protocol_adapter import parse_status_result

    profile = MODEL_PROFILES[model]
    for group, page in enumerate(_segment_pages(profile), start=1):
        result = parse_status_result(page, model)
        assert result.parsed is not None, (
            f"{model} page {group} is rejected by its own {profile.status_grammar} root "
            f"({getattr(result.rejection, 'value', None)}): the profile declares "
            f"{profile.segment_count} segments at {profile.segment_group_size} a page"
        )
        body = result.parsed.body
        offset = (group - 1) * profile.segment_group_size
        meaningful = min(profile.segment_group_size, profile.segment_count - offset)
        assert int(body.num_segments) >= meaningful, (
            f"{model} page {group}: the root reads {body.num_segments} records where the "
            f"profile expects {meaningful}, so the page cannot be applied"
        )
        assert int(body.num_segments) <= profile.segment_group_size, (
            f"{model} page {group}: the root reads {body.num_segments} records, more than the "
            f"profile's {profile.segment_group_size} per page"
        )


@pytest.mark.parametrize("model", _SEGMENT_MODELS)
def test_segment_pages_reach_observed_state(hass, model: str) -> None:
    """The same pages, end to end through the notification path, for the models whose runtime
    profile is not still waiting on capability resolution."""
    from custom_components.ha_govee_led_ble.coordinator import GoveeBLECoordinator

    coordinator = GoveeBLECoordinator(hass, "AA:BB:CC:DD:EE:FF", model, configuration_url="http://x")
    profile = coordinator.profile
    if not profile.supports_segments:
        pytest.skip(f"{model} resolves its segment capability at runtime; covered above")
    for page in _segment_pages(profile):
        coordinator._notify_callback(None, bytearray(page))
    assert coordinator.segment_state_source == "observed", (
        f"{model} declares {profile.segment_count} segments at {profile.segment_group_size} a page, "
        f"which its {profile.status_grammar} root does not read back"
    )
    assert coordinator.segment_colors == [(index + 1, 0, 0) for index in range(profile.segment_count)]
    assert coordinator.segment_brightness == [50 + index for index in range(profile.segment_count)]


_COORDINATOR_SOURCE = (
    Path(__file__).resolve().parent.parent / "custom_components" / "ha_govee_led_ble" / "coordinator.py"
).read_text(encoding="utf-8")


def _query_builders(model: str):
    """Every way this model could ask for a domain, so 'claimed but never asked' shows up."""
    from custom_components.ha_govee_led_ble import generated_protocol_adapter as a

    return {
        ReadDomain.POWER: [lambda: a.build_power_query(model)],
        ReadDomain.BRIGHTNESS: [lambda: a.build_brightness_query(model)],
        ReadDomain.COLOUR_MODE: [lambda: a.build_colour_mode_query(model)],
        ReadDomain.FIRMWARE: [lambda: a.build_firmware_query(model)],
        ReadDomain.HARDWARE: [lambda: a.build_hardware_query(model)],
        ReadDomain.SUBORDINATE_20: [lambda: a.build_subordinate_query(0x20, model)],
        ReadDomain.SUBORDINATE_21: [lambda: a.build_subordinate_query(0x21, model)],
        ReadDomain.SEGMENTS: [lambda: a.build_segment_query(1, model)],
        ReadDomain.DISPLAY_SETTING: [
            lambda: a.build_white_balance_query(model),
            lambda: a.build_blank_screen_query(model),
            lambda: a.build_black_border_query(model),
        ],
        ReadDomain.RELATIVE_BRIGHTNESS: [lambda: a.build_relative_brightness_query(model)],
        ReadDomain.IC_SEGMENT_COUNT: [lambda: a.build_ic_segment_count_query(model)],
        ReadDomain.INSTALLATION_DIRECTION: [lambda: a.build_installation_direction_query(model)],
        ReadDomain.CAMERA_HEALTH: [lambda: a.build_camera_health_query(model)],
    }


@pytest.mark.parametrize("model", _PROFILES_WITH_STATUS)
def test_every_claimed_read_domain_can_actually_be_asked_for(model: str) -> None:
    """A read domain nothing queries is a claim that reads as a feature and does nothing. It
    costs a reviewer's trust and, where the domain gates behaviour, it misleads the code that
    consults it."""
    builders = _query_builders(model)
    unaskable = []
    for domain in sorted(MODEL_PROFILES[model].read_domains, key=lambda d: d.value):
        candidates = builders.get(domain)
        if candidates is None:
            unaskable.append(f"{domain.value} (no query builder exists at all)")
            continue
        if not any(_builds(build) for build in candidates):
            unaskable.append(f"{domain.value} (no builder emits a frame for this model)")
    assert not unaskable, f"{model} claims read domains it can never request: {unaskable}"


def _builds(build) -> bool:
    try:
        return len(build()) == 20
    except Exception:
        return False


@pytest.mark.parametrize("model", _PROFILES_WITH_STATUS)
def test_every_claimed_read_domain_is_consumed(model: str) -> None:
    """The other half: a domain that is queried, parses, and then reaches no branch leaves the
    reply on the floor."""
    handled = {
        domain for name, domain in _STATUS_DOMAIN_NAMES.items() if f"StatusDomain.{domain.name}" in _COORDINATOR_SOURCE
    }
    # These reach the coordinator through their own handlers rather than the domain dispatch.
    handled |= {ReadDomain.INSTALLATION_DIRECTION, ReadDomain.CAMERA_HEALTH, ReadDomain.IC_SEGMENT_COUNT}
    unconsumed = sorted(d.value for d in MODEL_PROFILES[model].read_domains if d not in handled)
    assert not unconsumed, f"{model} claims read domains nothing consumes: {unconsumed}"


_REPO = Path(__file__).resolve().parent.parent


def test_no_committed_conflict_markers() -> None:
    """A conflicted merge resolved with `git add -A` commits the markers. A later commit can
    repair the file, leaving the suite green at the tip while an intermediate commit does not
    build at all -- invisible to every other test here, because they only ever run against the
    tip."""
    roots = ("custom_components", "tests", "tools", "scripts", "frontend/src")
    skip = {".build", "node_modules", "__pycache__", ".venv", "generated_protocol"}
    offenders = []
    for root in roots:
        base = _REPO / root
        if not base.is_dir():
            continue
        for path in base.rglob("*"):
            if not path.is_file() or skip & set(path.parts) or path.name == Path(__file__).name:
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError, OSError:
                continue
            # Both halves must be present: a lone row of equals signs is ordinary prose.
            if any(row.startswith("<" * 7) for row in lines) and any(row.startswith(">" * 7) for row in lines):
                offenders.append(str(path.relative_to(_REPO)))
    assert not offenders, f"conflict markers committed in: {sorted(offenders)}"


@pytest.mark.parametrize("model", _PROFILES_WITH_STATUS)
def test_scalar_white_balance_readback_has_a_typed_payload(model: str) -> None:
    """Declaring the scalar representation arms a reader that takes `.value` off the display
    setting payload. Where the root leaves that payload raw the reader raises AttributeError,
    and it does so inside the BLE notification callback, which swallows it: the reply is lost
    rather than degraded, and nothing in the suite notices."""
    from custom_components.ha_govee_led_ble.coordinator_status import decode_status_frame

    profile = MODEL_PROFILES[model]
    if not (profile.supports_white_balance_readback and profile.video_white_balance_representation == "scalar"):
        pytest.skip(f"{model} does not claim scalar white-balance readback")
    decoded = decode_status_frame(_xor(bytes([0xAA, 0xA9, 0x06, 0x01, 0x32]).ljust(19, b"\x00")), model)
    assert decoded is not None, f"{model} cannot parse its own `aa a9 06` reply"
    payload = decoded.generated.body.payload
    assert not isinstance(payload, (bytes, bytearray)), (
        f"{model} claims scalar white-balance readback, but its {profile.status_grammar} root "
        f"leaves the setting-6 payload as raw bytes, so reading `.value` raises inside the "
        f"notification callback"
    )
    assert int(payload.value) == 0x32


@pytest.mark.parametrize("model", sorted(m for m, p in MODEL_PROFILES.items() if p.supports_video_mode))
def test_every_declared_video_mode_can_be_built(model: str) -> None:
    """The read-domain checks above have a command-side twin. A profile can declare a video
    mode whose builder does not recognise the grammar it declares, and the effect list then
    advertises a mode that raises on every attempt -- which is what reached the owner's phone:
    `H66A0 has no generated video-mode grammar` on `light/turn_on`.
    """
    from custom_components.ha_govee_led_ble import generated_protocol_adapter as a
    from custom_components.ha_govee_led_ble.generated_protocol_adapter import H66a0VideoCommand

    profile = MODEL_PROFILES[model]
    assert profile.video_modes, f"{model} claims video mode without naming any"
    # Grammars that encode device-specific picture values need them supplied; the runtime takes
    # them from the device's last read, and the test supplies a valid pair.
    values = (
        {"picture_preset": next(iter(H66a0VideoCommand.PicturePreset.__members__)), "opaque": 0}
        if profile.video_grammar == "H66A0-video"
        else {}
    )
    for mode in profile.video_modes:
        frame = a.build_video_mode(mode, True, 50, False, 50, model, values=values)
        assert len(frame) == 20, f"{model} video mode {mode} built {len(frame)} bytes"
