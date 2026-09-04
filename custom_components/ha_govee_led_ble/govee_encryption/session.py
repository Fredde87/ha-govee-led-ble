"""Connection-scoped state for the Govee ``0xE711`` AES-GCM scheme.

One :class:`GoveeEncryptionSession` belongs to one BLE connection. The counters and both
``ivKey`` nonces are negotiated per connection, so a reconnect that reused them would fail
every GCM tag check from the first frame onwards; :meth:`reset` is therefore called on
every disconnect and :meth:`async_negotiate` on every connect.

Nothing here raises into the coordinator. A device that does not offer the ``2b12``
marker, a marker that does not say version 2, a refused or timed-out handshake and a frame
that fails its tag all end in the same place: the plaintext path the integration used
before this package existed.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import warnings
from dataclasses import asdict, dataclass
from typing import Any

from ..transport import WRITE_UUID
from . import crypto_v1
from .crypto import (
    ENCRYPTION_VERSION_AES_GCM,
    HOST_COUNTER_START,
    MIN_MTU,
    UUID_ENC_VERSION,
    GoveeCryptoError,
    build_handshake,
    derive_device_key,
    is_handshake_response,
    parse_encryption_version,
    parse_handshake_response,
    seal,
    unseal,
)

_LOGGER = logging.getLogger(__name__)

# The app waits 6000 ms for the session key; matching it means a device that is simply slow
# is not written off as unencrypted.
HANDSHAKE_TIMEOUT = 6.0

# The v1 probe is paid by every device that is NOT v2, including the plaintext models this
# integration has always supported, so its cost lands on existing users and has to be small.
# It is one extra frame plus this timeout. A real v1 device answers fast -- 29 ms in the
# capture that identified the scheme -- so two seconds is roughly seventy times the observed
# latency while keeping the worst case for a plaintext device to a couple of seconds once per
# connection. The alternative is not "no cost": it is sending plaintext to a v1 device, which
# it accepts at ATT and silently ignores.
V1_HANDSHAKE_TIMEOUT = 2.0
# The confirm ack is not load-bearing -- the session key is already in hand -- so this only
# has to be long enough not to race a prompt device.
V1_CONFIRM_TIMEOUT = 1.0

# How long a device that answered the v1 probe with silence is taken at its word.
#
# The cache exists because reconnects are frequent and re-probing a genuinely plaintext device
# forever would make V1_HANDSHAKE_TIMEOUT a permanent per-connection tax. But silence within
# two seconds is weaker evidence than it looks: a v1 device that is momentarily busy, or whose
# notification subscription has not settled, produces exactly the same silence as a device that
# has no v1 support at all -- and the consequence of getting it wrong is not a slow device, it
# is a device that acknowledges every command and ignores it.
#
# So the answer is remembered, but not forever. A plaintext device pays one probe per quarter
# hour instead of one per connection, which keeps the cost a rounding error; a v1 device that
# was misread recovers by itself within the same quarter hour instead of staying mute until
# somebody reloads the config entry.
#
# Observed 2026-09-10: an H61F5 spent a full day acknowledging and ignoring every command,
# including its owner trying to switch it off, because one probe early that morning timed out
# and the verdict was permanent. See _v1_confirmed for the other half of that fix.
V1_RULED_OUT_TTL = 900.0

# The ATT default. bleak's BlueZ backend reports exactly this, and warns, until its private
# _acquire_mtu() has run -- which nothing in Home Assistant calls. The real MTU on the one
# device we can test is 512. Treating the placeholder as "too small" would therefore switch
# encryption off on every BlueZ install while looking entirely correct, so it is read as
# "unknown" instead. See _mtu_rejects().
BLE_DEFAULT_MTU = 23


@dataclass(frozen=True, slots=True)
class NegotiationResult:
    """The outcome of one key negotiation, kept after the session it belonged to is gone.

    ``mtu_reported`` is what the backend said, not what the link actually carries -- bleak's
    BlueZ backend reports the 23-byte ATT default until its private ``_acquire_mtu`` has run,
    and nothing in Home Assistant calls that. A 23 here means "unknown", not "too small".
    """

    succeeded: bool
    encryption_version: int
    sku: str | None
    mtu_reported: int | None
    notifications_seen: int
    reason: str | None


class GoveeEncryptionSession:
    """Encrypts and decrypts command frames for one BLE connection, when the device asks.

    The three entry points are :meth:`async_negotiate` on connect, :meth:`encode` on every
    write and :meth:`decode` on every notification. All three are safe to call on a device
    that never negotiated: they pass the bytes through untouched.
    """

    def __init__(self, address: str) -> None:
        self.address = address
        self.sku: str | None = None
        self.encryption_version = 0
        self._device_key: bytes | None = None
        self._v1_key: bytes | None = None
        self._v1_negotiating = False
        self._client_iv_key: bytes | None = None
        self._device_iv_key: bytes | None = None
        self._counter = HOST_COUNTER_START
        self._handshake: asyncio.Future[bytes] | None = None
        self._undecryptable = 0
        # Diagnostic only. A negotiation that times out has to be able to say whether the
        # notify characteristic was delivering anything at all: "the device never answered"
        # and "notifications are not reaching us" are different faults with the same symptom,
        # and a bare timeout cannot tell them apart.
        self._notifications_seen = 0
        self._mtu = 0
        # When the v1 probe's silence stops being taken at its word; None when it has not
        # drawn silence. A device's encryption generation really is a property of its firmware
        # rather than of the connection, so caching the answer is right -- but only a device
        # that ANSWERS states its generation, and silence is not an answer, merely the absence
        # of one within two seconds. Hence a deadline rather than a latch: see V1_RULED_OUT_TTL.
        self._v1_ruled_out_until: float | None = None
        # STICKY, and never cleared -- not by reset(), not by a later failure, not by anything
        # short of rebuilding this object. A successful v1 handshake is the one piece of
        # evidence here that cannot be produced by accident: the device returned a session key
        # under the app-global communication key, so it IS a v1 device, whatever a later probe
        # does or does not manage to elicit.
        #
        # That fact is load-bearing rather than informational, because the fallback this class
        # exists to choose is not safe for such a device. Plaintext to a v1 device is accepted
        # at ATT and silently discarded, so falling back turns every command into a lie: the
        # write succeeds, the entity updates, and the light does not move. Once this is set,
        # writes_would_be_ignored refuses that outcome and the caller gets an error it can
        # retry or show, which is strictly better than a command that reports success.
        self._v1_confirmed = False
        # STICKY. Deliberately not cleared by reset(), which runs on every disconnect --
        # including the routine 120-second idle one. Live session state is None or False for
        # most of a device's life, so a diagnostics download taken while idle would otherwise
        # report "encryption off" for a device that encrypts every frame. That is precisely
        # backwards for the first artifact anybody asks a user to send.
        self.last_negotiation: NegotiationResult | None = None

    @property
    def active(self) -> bool:
        """True once a session key is in force and frames are being encrypted."""
        return self._device_key is not None or self._v1_key is not None

    @property
    def _v1_ruled_out(self) -> bool:
        """True while a recent silence from the v1 probe is still being taken at its word."""
        deadline = self._v1_ruled_out_until
        return deadline is not None and time.monotonic() < deadline

    @property
    def writes_would_be_ignored(self) -> bool:
        """True when sending a frame now would be accepted by the device and discarded.

        The one case is a device known to speak v1 -- proven by a handshake it completed --
        that has no session key in force right now. Every frame the transport sends in that
        state goes out in plaintext, and a v1 device acks plaintext at ATT and does nothing
        with it, so the write reports success and the light never moves.

        The transport reads this instead of writing, so the caller gets a failure it can act
        on. Recovery is a reconnect away: negotiation runs again on the next connect, and the
        probe is not cached against a device that has already proven itself.
        """
        return self._v1_confirmed and self._v1_key is None

    def reset(self) -> None:
        """Forget the session. Called on every disconnect, and after any failure."""
        if (handshake := self._handshake) is not None and not handshake.done():
            # Failed rather than cancelled on purpose. A disconnect can land while a
            # handshake is in flight, and cancelling here would raise CancelledError inside
            # async_negotiate -- which is a BaseException, so it would escape the guards
            # there and surface out of _start_notify as something the coordinator has no
            # handler for. A GoveeCryptoError lands on the plaintext fallback like every
            # other failure. exception() is read immediately so a future nobody ends up
            # awaiting cannot log "exception was never retrieved" on garbage collection;
            # the await in _async_negotiate still re-raises it.
            handshake.set_exception(GoveeCryptoError("disconnected while negotiating"))
            handshake.exception()
        self._handshake = None
        self._device_key = self._client_iv_key = self._device_iv_key = None
        self._v1_key = None
        self._v1_negotiating = False
        self._counter = HOST_COUNTER_START
        self._undecryptable = 0
        self._notifications_seen = 0
        self._mtu = 0
        self.sku = None
        self.encryption_version = 0

    async def async_negotiate(self, client: Any) -> None:
        """Probe ``2b12`` and, if the device wants encryption, exchange a session key.

        Must run after ``start_notify`` -- the device answers the handshake on the notify
        characteristic, which :meth:`decode` picks up. Never raises: every failure leaves
        the session inactive, which is the plaintext path.
        """
        self.reset()
        try:
            await self._async_negotiate(client)
        except (GoveeCryptoError, TimeoutError) as err:
            # TimeoutError stringifies to nothing, so the reason is built rather than
            # interpolated, and the counters go with it. "Key negotiation failed ()" is not
            # something anybody can act on from a log file, which is the only instrument a
            # user reporting this will have.
            reason = str(err) or f"no handshake response within {HANDSHAKE_TIMEOUT:g}s"
            self._record_negotiation(succeeded=False, reason=reason)
            _LOGGER.warning(
                "%s reports encryption version %s but key negotiation failed: %s "
                "(%d notification(s) arrived during negotiation, MTU reported as %s). Falling "
                "back to plaintext, which a device that asked for encryption is likely to ignore",
                self.address,
                self.encryption_version,
                reason,
                self._notifications_seen,
                self._mtu or "unknown",
            )
            self.reset()
        except Exception as err:
            # Deliberately broad. A device that answers the marker read with something
            # unexpected, or a backend without a service table, must cost this integration a
            # debug line and nothing else. CancelledError is a BaseException and is not caught
            # here, so task cancellation still propagates; _device_key is only assigned once
            # every step has succeeded, so a half-finished negotiation can never read as active.
            self._record_negotiation(succeeded=False, reason=f"{type(err).__name__}: {err}")
            _LOGGER.debug("Encryption probe failed for %s: %s", self.address, err)
            self.reset()

    async def _async_negotiate(self, client: Any) -> None:
        version = await self._async_read_version(client)
        self.encryption_version = version
        if version != ENCRYPTION_VERSION_AES_GCM:
            # Not v2 -- but "not v2" is not "plaintext", and treating it as such is a bug
            # with a nasty presentation. A v1 device accepts a plaintext write at the ATT
            # layer, acknowledges it, and does nothing: the light connects, every entity
            # populates, every command reports success and the strip never moves. An H61F5
            # did exactly that to this project for five sessions before v1 was identified.
            #
            # The marker cannot be trusted to tell us either. BgcInfoReader treats version 1
            # and 2 alike as "encrypted", but the H61F5 that forced this has NO 2b12
            # characteristic at all and so reports 0 -- indistinguishable from the genuinely
            # plaintext models. So the probe has to be the handshake itself.
            if await self._async_negotiate_v1(client):
                return
            _LOGGER.debug("%s: encryption version %s, using plaintext", self.address, version)
            self._record_negotiation(succeeded=False, reason="device does not ask for encryption")
            return
        if self._mtu_rejects(client):
            return
        self._client_iv_key = os.urandom(8)
        self._handshake = asyncio.get_running_loop().create_future()
        await client.write_gatt_char(WRITE_UUID, build_handshake(self._client_iv_key), response=False)
        async with asyncio.timeout(HANDSHAKE_TIMEOUT):
            response = await self._handshake
        device_iv_key, sku, mac_wire_order = parse_handshake_response(response)
        self._device_iv_key = device_iv_key
        self._device_key = derive_device_key(sku, mac_wire_order)
        self.sku = sku.decode("ascii", "replace")
        self._record_negotiation(succeeded=True)
        # Deliberately no MAC and no key in the log: both identify the physical device, and
        # the key is reconstructible from the pair. The SKU is a model name and is safe.
        _LOGGER.debug(
            "%s: encrypted session established, sku=%s, host counter starts at %s",
            self.address,
            self.sku,
            self._counter,
        )

    async def _async_negotiate_v1(self, client: Any) -> bool:
        """Attempt the v1 handshake. ``True`` when a session key is in force.

        Never raises, and leaves nothing behind when it fails. Silence is the expected
        outcome on every plaintext device this integration already supports, so it is
        treated as an ordinary answer rather than an error: one frame, one short wait, then
        the plaintext path exactly as before.
        """
        if self._v1_ruled_out:
            _LOGGER.debug(
                "%s: v1 ruled out %.0fs ago, not re-probing until that expires",
                self.address,
                V1_RULED_OUT_TTL - max(0.0, (self._v1_ruled_out_until or 0.0) - time.monotonic()),
            )
            return False
        self._v1_negotiating = True
        try:
            self._handshake = asyncio.get_running_loop().create_future()
            await client.write_gatt_char(WRITE_UUID, crypto_v1.build_session_request(), response=False)
            async with asyncio.timeout(V1_HANDSHAKE_TIMEOUT):
                response = await self._handshake
            key = crypto_v1.parse_session_key(response)
            # The app follows with 0xE7 0x02 and the device acks it. The key is already in
            # hand by then, so a missing ack is not a failed negotiation -- but the frame is
            # sent anyway, because matching the app's sequence costs one write and avoids
            # depending on a device tolerating a step the vendor never skips.
            self._handshake = asyncio.get_running_loop().create_future()
            await client.write_gatt_char(WRITE_UUID, crypto_v1.build_confirm(), response=False)
            try:
                async with asyncio.timeout(V1_CONFIRM_TIMEOUT):
                    await self._handshake
            except TimeoutError:
                _LOGGER.debug("%s: v1 confirm unacknowledged, continuing", self.address)
        except (GoveeCryptoError, TimeoutError) as err:
            if self._v1_confirmed:
                # This device has completed a v1 handshake before, so it is a v1 device and
                # silence now is a fault, not a generation. Nothing is cached -- the next
                # connection asks again -- and the warning is deliberate: plaintext is not a
                # working fallback here, so the caller is about to start seeing write failures
                # and this is the line that explains them. writes_would_be_ignored is what
                # actually stops the plaintext frames.
                _LOGGER.warning(
                    "%s has negotiated encryption v1 before but did not answer the handshake "
                    "this time (%s). Commands will fail rather than be sent in plaintext, "
                    "which this device acknowledges and ignores; the next reconnect retries",
                    self.address,
                    err or "timed out",
                )
                return False
            # A clean "no" -- the device was asked properly and said nothing. Remember it, but
            # only for a while: silence is the same shape from a plaintext device and from a
            # v1 device that was busy for two seconds. See V1_RULED_OUT_TTL.
            self._v1_ruled_out_until = time.monotonic() + V1_RULED_OUT_TTL
            _LOGGER.debug("%s: no v1 handshake (%s), using plaintext", self.address, err or "timed out")
            return False
        except Exception as err:  # noqa: BLE001 -- a probe must never take the connection down
            # NOT cached: a write that failed, a backend that raised, a disconnect mid-probe.
            # None of those is the device answering, so none of them is evidence about it.
            _LOGGER.debug("%s: v1 probe failed: %s", self.address, err)
            return False
        finally:
            self._v1_negotiating = False
            self._handshake = None
        self._v1_key = key
        # Proven, and therefore permanent: see _v1_confirmed. Any earlier silence is now known
        # to have been a fault rather than an answer, so the cache holding it is dropped too.
        self._v1_confirmed = True
        self._v1_ruled_out_until = None
        self.encryption_version = crypto_v1.ENCRYPTION_VERSION_V1
        self._record_negotiation(succeeded=True)
        # No key in the log: it is the whole session secret. The v2 path logs the SKU here,
        # which v1 does not carry -- its handshake reply is key material and nothing else.
        _LOGGER.debug("%s: v1 encrypted session established", self.address)
        return True

    def _record_negotiation(self, *, succeeded: bool, reason: str | None = None) -> None:
        self.last_negotiation = NegotiationResult(
            succeeded=succeeded,
            encryption_version=self.encryption_version,
            sku=self.sku,
            mtu_reported=self._mtu or None,
            notifications_seen=self._notifications_seen,
            reason=reason,
        )

    def diagnostics(self) -> dict[str, Any]:
        """What a bug report needs about this session, live state and last outcome both.

        Split deliberately. ``active`` answers "is a key in force right now", which is False
        on an idle device and says nothing about whether encryption works. ``last_*`` answers
        "what happened the last time we asked", which is the question the reader has.
        """
        last = self.last_negotiation
        return {
            "active": self.active,
            "encryption_version": self.encryption_version,
            "sku": self.sku,
            "mtu_reported": self._mtu or None,
            "notifications_seen": self._notifications_seen,
            "undecryptable_frames": self._undecryptable,
            # Both halves of the v1 fallback decision, because "the light acknowledges
            # everything and does nothing" is the report these answer. v1_confirmed says the
            # device has proven itself a v1 device, so plaintext to it is discarded and writes
            # are refused rather than sent; v1_probe_suppressed says a recent silence is still
            # being taken at its word and the probe is not being repeated yet.
            "v1_confirmed": self._v1_confirmed,
            "v1_probe_suppressed": self._v1_ruled_out,
            "writes_would_be_ignored": self.writes_would_be_ignored,
            "last_negotiation": None if last is None else asdict(last),
        }

    async def _async_read_version(self, client: Any) -> int:
        """Read the ``2b12`` marker, or 0 when the device does not have one.

        Checked against the discovered service table first, so a device without the
        characteristic -- every model this integration supported before now -- costs no
        round trip and puts nothing on the wire.
        """
        if client.services.get_characteristic(UUID_ENC_VERSION) is None:
            _LOGGER.debug("%s: no 2b12 characteristic, using plaintext", self.address)
            return 0
        blob = bytes(await client.read_gatt_char(UUID_ENC_VERSION))
        _LOGGER.debug("%s: 2b12 marker = %s", self.address, blob.hex())
        return parse_encryption_version(blob)

    def _mtu_rejects(self, client: Any) -> bool:
        """True only for an MTU that is reported *and* genuinely below the single-frame floor.

        A backend that does not know the MTU reports the ATT default, which is
        indistinguishable from a device that really negotiated it. Both proceed: an
        undersized write simply produces no handshake response and the timeout above lands
        on the same plaintext fallback, six seconds later and once per connection.
        """
        with warnings.catch_warnings():
            # bleak's BlueZ backend warns on every read of an unacquired MTU.
            warnings.simplefilter("ignore")
            mtu = int(getattr(client, "mtu_size", 0) or 0)
        self._mtu = mtu
        if BLE_DEFAULT_MTU < mtu < MIN_MTU:
            _LOGGER.warning(
                "%s negotiated MTU %s, below the %s this scheme needs; using plaintext",
                self.address,
                mtu,
                MIN_MTU,
            )
            return True
        _LOGGER.debug("%s: MTU reported as %s", self.address, mtu or "unknown")
        return False

    def encode(self, packet: bytes) -> bytes:
        """Wrap one command frame for the wire, or return it unchanged when inactive."""
        if self._v1_key is not None:
            return crypto_v1.encrypt(packet, self._v1_key)
        if self._device_key is None or self._client_iv_key is None:
            return packet
        sealed = seal(packet, self._client_iv_key, self._device_key, self._counter)
        self._counter += 1
        return sealed

    def decode(self, frame: bytes) -> bytes | None:
        """Unwrap one notification.

        Returns the plaintext command frame, or ``None`` when the frame was consumed by the
        handshake or could not be authenticated. An inactive session passes frames straight
        through, which is what keeps the plaintext models on their existing path.
        """
        self._notifications_seen += 1
        if is_handshake_response(frame):
            if (handshake := self._handshake) is not None and not handshake.done():
                handshake.set_result(frame)
            else:
                _LOGGER.debug("%s: unexpected 0xE711 frame, no handshake pending", self.address)
            return None
        if self._v1_negotiating and (negotiation := crypto_v1.parse_negotiation_frame(frame)) is not None:
            # Mid-v1-handshake every frame is still under the app-global key. A frame that
            # does not decrypt to a well-formed 0xE7 under it is deliberately NOT swallowed:
            # on a plaintext device that is just an ordinary reply arriving while the probe
            # is in flight, and dropping it would break the very models this must not affect.
            _command, plain = negotiation
            if (handshake := self._handshake) is not None and not handshake.done():
                handshake.set_result(plain)
            return None
        if self._v1_key is not None:
            try:
                plain = crypto_v1.decrypt(frame, self._v1_key)
            except Exception as err:  # noqa: BLE001 -- inside bleak's notification callback
                self._undecryptable += 1
                _LOGGER.debug("%s: v1 frame could not be decrypted: %s", self.address, err)
                return None
            if not crypto_v1.checksum_ok(plain):
                # v1 has no authentication tag, so the XOR checksum is the only integrity
                # signal there is. It is weak, but a frame that fails it is certainly not a
                # command and must not reach the decoder.
                self._undecryptable += 1
                _LOGGER.debug("%s: dropped a v1 frame failing its checksum", self.address)
                return None
            _LOGGER.debug("%s: rx v1 plaintext=%s", self.address, plain.hex())
            return plain
        if self._device_key is None or self._device_iv_key is None:
            return frame
        try:
            counter, plain = unseal(frame, self._device_iv_key, self._device_key)
        except GoveeCryptoError as err:
            self._undecryptable += 1
            _LOGGER.debug(
                "%s: dropped an unauthenticated notification (%s so far this session): %s",
                self.address,
                self._undecryptable,
                err,
            )
            return None
        _LOGGER.debug("%s: rx counter=%s plaintext=%s", self.address, counter, plain.hex())
        return plain
