# Govee BLE command surface (the 20-byte `0x33` / `0xAA` / `0xEE` protocol)

Companion to [`PROTOCOL.md`](PROTOCOL.md). That document covers the **transport**
— the `0xE711` AES-GCM wrapper used by newer devices. This document covers the
**payload**: the classic 20-byte Govee command language, which is identical
whether or not it is encrypted underneath.

Sources, and how to tell them apart:

* **decompiled Govee Home 7.5.30** (`com.govee.base2light.ble.controller.*` and
  the per-product `com.govee.*` modules)
* **two PacketLogger captures** of the iOS app driving a real **H66A0** (TV
  Backlight 3 Pro), decrypted in full — see `decrypt_capture.py`
  * `Govee Capture.pklg` — 99 frames: power, brightness, colour, queries
  * `capture2.pklg` — 1022 frames: **scenes, DIY, DIY graffiti, music**,
    timers, sleep. It has no handshake; see `PROTOCOL.md` §8 for how it was
    decrypted anyway
* **live testing** against that same H66A0 from `govee_v3.py`
* cross-checks against [`Beshelmek/govee_ble_lights`](https://github.com/Beshelmek/govee_ble_lights)
  and [`wez/govee2mqtt`](https://github.com/wez/govee2mqtt), which encode the
  same frames independently

## Confidence marking

Every entry below carries one of:

* **verified** — observed on real hardware, or decrypted from our capture
* **from APK** — read out of decompiled code, never seen on the wire here
* **inferred** — reasoned from adjacent evidence; the reasoning is stated

Nothing that would be a guess is in this document. Where we do not know
something, it says so.

`decode_commands.py` regenerates every **verified** claim from the capture:

```
$ python3 decode_commands.py "Govee Capture.pklg"
...
named: 99   unknown: 0   bad frames: 0

$ python3 decode_commands.py capture2.pklg
...
named: 1022   unknown: 0   bad frames: 0
```

**Both captures now decode completely.** Everything either capture contains is
named. What we do *not* have is coverage: §8 lists the frame shapes and commands
that exist in the APK but have never appeared in a trace.

**These two counts were audited on 2026-08-24 and one of them had been right by
accident.** The named/unknown tally tested `'UNKNOWN' in text`, but the
colour-dialect describer emits a lower-case `(unknown)` — so any colour sub-type
it could not name was counted as *named*. Capture 2 was hiding 36 frames that
way (`33 05 15 04`, now documented in §2.3.4); with the counter fixed and those
frames still unnamed it read `986 named, 36 unknown`. Capture 1 contains no such
frame and its 99 was always correct. Both figures above are now produced by a
counter that matches case-insensitively, so they mean what they say.

The decryption figures are a different check and were never affected: 99/99
valid GCM tags is a tag verification, not a naming pass.

---

## 1. Frame anatomy

**verified** (every frame in the capture; and by three independent
implementations)

```
off  size  field
0    1     header
1    1     command
2    17    payload (zero-padded)
19   1     checksum = XOR of bytes 0..18
```

Always exactly 20 bytes, always padded, always checksummed. Built by
`BleUtils.generate20Bytes(header, command, payload)`; the checksum is
`BleUtils.getBCC(frame, 19)`.

**This is not the only frame shape.** `AbsMicController` bypasses
`generate20Bytes` entirely and emits **variable-length** frames with a **byte
sum** instead of the XOR — see §2.9. A decoder that assumes 20 bytes and an XOR
checksum will reject those as corrupt. They are rare but real: one appears in
capture 2.

| Header | Meaning | Direction |
|---|---|---|
| `0x33` | SET — write a value | host → device |
| `0xAA` | GET — read a value | host → device, and the device's reply |
| `0xEE` | device-pushed event | device → host |
| `0xA1` / `0xA2` | multi-packet write / read (`MULTIPLE_WRITE` / `MULTIPLE_READ`) | host → device |
| `0xA3` | multi-packet write, v1 — the one scenes use | host → device |
| `0xA4` | multi-packet write, v2 | host → device |

Beware `0xA3`: it is a multi-packet **header** in byte 0, and separately a
**command** byte (gradual change, §2.6) in byte 1 of an ordinary `0x33`/`0xAA`
frame. Position disambiguates; the two are unrelated.

`0x33` and `0xAA` are the same command space: `AbsSingleController.getProType()`
returns `0x33` when writing and `0xAA` when reading, for the same command byte.

**Replies.** A `0xAA` read is answered by a `0xAA` frame with the same command
byte and the value in the payload. A `0x33` write is answered by a `0x33` frame
with the same command byte where **payload[0] is the result code, `0` = OK**
(`AbsSingleController.t()`: `bArr[2] == 0`). **verified** — every SET in the
capture is followed by exactly this echo.

### Reading this table

The command byte space is **shared, and overloaded per product family**. The
same byte means different things on a bulb, a string light and a TV backlight.
The table below is the `com.govee.base2light.ble.controller` common set — the
shared light protocol, which is what an H66A0 and its relatives speak. Where a
family diverges, that is called out. Do not assume a command from this table
exists, or means the same thing, on an unrelated SKU.

---

## 2. Command table

### 2.1 Power — `0x01`

**verified**

```
33 01 <00|01>          off / on
aa 01                  query
aa 01 <00|01>          reply
```

`SwitchController`. The device also pushes an `0xEE30` event on change (§4).

### 2.2 Brightness — `0x04`

**verified** (H66A0 takes 0–100; observed `3304 25` = 37, and `aa04` → `0x64`
= 100 at full brightness)

```
33 04 <level>          set
aa 04                  query
aa 04 <level>          reply
```

`BrightnessController` writes the byte unchanged; **the scale is decided by the
caller, not by the controller.** See §3.2 — this is the single most important
per-model difference and it *is* discoverable at runtime.

### 2.3 Mode — `0x05`

**verified** for the sub-modes seen on H66A0; **from APK** for the rest.

```
33 05 <sub-mode> <sub-mode payload...>
aa 05                  query      (the Android app sends payload 01; iOS sends 00)
aa 05 <sub-mode> <state...>        reply
```

`payload[0]` selects the sub-mode. The rest is sub-mode specific.

| Sub-mode | Meaning | Notes |
|---|---|---|
| `0x02` | colour (single-zone RGB) | older RGB devices |
| `0x04` | scene | |
| `0x0a` | DIY | |
| `0x0b` | colour (RGBIC, segment bitmask) | older RGBIC |
| `0x0d` | colour (RGB + colour temperature) | single-zone RGBWW |
| `0x13` | music | |
| `0x15` | colour (RGBIC, type-tagged) | **what H66A0 uses** |
| `0x16` | music (abstract/newer) | `SubModeAbsMusic` |
| `0x05`, `0x0c`, `0x0e`, `0x0f`, `0x11`, `0x14` | music/colour variants | family-specific; see §2.3.6 |

Sub-mode numbering is **not** globally consistent: `0x05` is a mic mode on
H6185 and a music mode elsewhere. The list above is the base2light set.

#### 2.3.1 Colour dialect `0x02` — plain RGB — **from APK**

```
33 05 02 RR GG BB <white:0|1> RR GG BB
                              └─ the RGB rendering of the white/CCT setting
```

This is the dialect `Beshelmek/govee_ble_lights` calls `LedMode.MANUAL`.

#### 2.3.2 Colour dialect `0x0b` — RGBIC with segment bitmask — **from APK**

```
33 05 0b RR GG BB <segmask 7:0> <segmask 14:8>
```

15 segments maximum (the APK's builder loops `i < 15`). Used by
`dreamcolorlightv1/v2`, `bulblightstringv1`, `pact_tvlightv2`.

#### 2.3.3 Colour dialect `0x0d` — RGB + Kelvin — **from APK**

```
33 05 0d RR GG BB <kelvin BE16> RR GG BB
                                └─ the RGB rendering of that colour temperature
```

No segments. Used by `tvlightv1`, `homelightv1`, `carlightv1`, `h6057` and others.

#### 2.3.4 Colour dialect `0x15` — RGBIC, type-tagged — **verified**

This is the H66A0 dialect. `payload[1]` is a **type** selector:

```
type 1 — colour and/or colour temperature
33 05 15 01 RR GG BB <kelvin BE16> RR GG BB <segmask 7:0> <segmask 15:8>
            │        │             │        └─ 16-bit little-endian segment mask
            │        │             └─ RGB rendering of the colour temperature
            │        └─ 0 when setting a plain RGB colour
            └─ 00 00 00 when setting a colour temperature

type 2 — brightness for selected segments
33 05 15 02 <brightness> <segmask 7:0> <segmask 15:8>

type 3 — per-segment brightness array
33 05 15 03 <bri seg1> <bri seg2> ...

type 4 — per-segment colour, paged
33 05 15 04 <page 1-based> <RR GG BB> x 4
```

**Type 4 is new here (2026-08-24), and was hiding in plain sight.** It is the
write-side twin of the `aa a5` read: one page index and four RGB triplets, four
pages covering an H66A0's 14 segments as 4 + 4 + 4 + 2. 36 of these appear in
capture 2 and `decode_commands.py` reported them as named for months — its
counter tested for an upper-case `UNKNOWN` while the colour-dialect describer
emitted a lower-case `(unknown)`, so every unrecognised type slipped the count.
Both are fixed; see the note under §1.

Decoded, one run resolves into a smooth hue ramp across segments 1..14, which is
what confirms the reading:

```
33 05 15 04 01 93e244 81e970 6ff09d 5df7c9   seg 1-4
33 05 15 04 02 4cfff6 5ed0f1 70a1ed 8272e9   seg 5-8
33 05 15 04 03 9544e5 aa45c8 bf47ac d44890   seg 9-12
33 05 15 04 04 e94a74 ff4c58 000000 000000   seg 13-14, then padding
```

This is a different mechanism from type 1 with a segment mask: type 1 addresses
an arbitrary set of segments with **one** colour, so painting *n* distinct
colours costs *n* frames; type 4 addresses every segment with its own colour at
a fixed cost of one frame per page. The app uses type 4 for a full repaint.

**Every paged run is preceded by `33 a3 00` — gradual change off.** Nine runs in
capture 2, nine preludes, 9 x 4 = the 36 frames exactly; not one paged run
occurs without it. Gradual change is a cross-fade, so painting adjacent segments
different colours with it enabled smears them into each other. A client that
writes type 4 (or a multi-frame type 1 run -- one of those gets the same prelude)
without turning it off first will render differently from the app on any device
where it happens to be on. See §2.6 for the register.

Both of the capture's colour commands decode exactly:

```
3305 1501 000000 0a8c ffae54 ff3f   →  colour temperature 2700 K (#ffae54), all 14 segments
3305 1501 0000ff 0000 000000 ff3f   →  blue,                                all 14 segments
```

`0x3FFF` = 14 bits = 14 segments, and the app's builder allocated a 14-element
segment array — so the H66A0 has **14 segments**. The colour temperature is
**big-endian**; the segment mask is **little-endian**. (`getSignedBytesFor2(x,
true)` is big-endian, `false` is little-endian.)

Note `Beshelmek/govee_ble_lights` sends this dialect with mask `0xFF7F`
(= 0x7FFF, 15 segments) for its segmented models — a superset that also works,
since surplus bits address segments that do not exist.

**Reply layout differs from the write.** `aa 05` on a `0x15` device answers:

```
aa 05 15 <?> <kelvin BE16, zone 1> <kelvin BE16, zone 2> ...
```

**verified**: the capture's reply `aa05 15 00 10cc 0000` = 4300 K, matching the
`#ffcb8d` the segments read back as. The byte at `payload[1]` is `0x00` in the
reply and we do not know what it carries — the app's parser skips it.

#### 2.3.5 Scenes — sub-mode `0x04` — **verified**

```
33 05 04 <sceneId little-endian 16> [<musicCode little-endian 16>]
```

For **built-in** scenes that is the whole story. For **parameterised** scenes —
the ones the model JSONs carry a base64 `scenceParam` for — the parameter blob
is uploaded first as a multi-packet write (§5), *then* activated with the
`33 05 04` frame above.

Both halves are now **verified on the wire**. Capture 2 contains 52 scene
activations: 49 immediately preceded by a `0xA3` type-`0x02` parameter upload,
and 3 sent bare (`id` 0, 15, 22 — low ids, which are exactly the firmware's
built-in table, see `RgbIcScenesV3`). 49 + 3 = 52, and the capture contains
exactly 49 type-`0x02` uploads, so the two sides balance. That is direct
confirmation that built-in scenes need no upload and cloud scenes do.

The two bytes after the id are a **16-bit `musicCode`**, not a variant
selector — **from APK**, and this corrects an earlier reading in this document.
Two builders emit this frame:

* `com.govee.pact_tvlightv3.ble.SubModeScenes.getWriteBytes()` — the H66A0's
  own family — returns exactly three bytes, `{4, id_lo, id_hi}`, and stops.
  The rest of the 20-byte frame is the usual zero padding.
* `com.govee.base2light.pact.newdetail.content.scene.SubModeScenes` — the newer
  Compose detail UI — appends `getSignedBytesFor2(this.c ? this.b : 0, false)`,
  where `this.b` is set by `setMusicCode(int)` and read by `getMusicCode()`.
  `getSignedBytesFor2(x, false)` is little-endian (`BleUtil`), so those are
  `musicCode` lo/hi. It has an eight-byte form too, gated on a flag, which
  widens the code to 32 bits and adds a trailing byte.

On the wire, 49 of the 52 carry `00 00` there and 3 carry `02 00` (scene ids
14353/14359/14371) — i.e. `musicCode` 0 and `musicCode` 2. Both method names
survive obfuscation, which is what makes this an identification rather than a
plausible reading. **Which app path sets a non-zero code, and what the device
does with it, is not established.**

The earlier reading here tied `02` to the model JSON's `specialEffect` entries.
That does not hold: `specialEffect[]` is a **per-SKU** list — every entry
carries its own `supportSku` — so it selects which SKU's parameter blob to
upload, not a variant of the activation frame. The app uploaded a `specialEffect`
blob ahead of the `00 00` activations too.

**Implementers should send the three-byte form** — `33 05 04 <lo> <hi>`, rest
zero. It is what 49 of the 52 captured activations look like, and what the
H66A0's own family emits. `wez/govee2mqtt`'s `SetSceneCode::encode` sends
exactly that, after a multi-packet upload on `0xA3` with header `[0x02]` —
independent confirmation of both halves.

`Beshelmek/govee_ble_lights` sends the multi-packet upload but **not** the
trailing `33 05 04` activation. That is worth knowing if you are debugging why a
scene uploads but does not visibly apply.

**Mapping to the model JSONs.** In `custom_components/govee-ble-lights/jsons/<SKU>.json`:

```
data.categories[].scenes[].sceneId                       → the 16-bit id
data.categories[].scenes[].lightEffects[].scenceParam    → base64 parameter blob
data.categories[].scenes[].lightEffects[].specialEffect[].scenceParam
                                                         → per-SKU blob; each
   entry carries its own supportSku, so the entry to upload is the one whose
   supportSku lists this device's model
```

These files come from Govee's cloud scene API. They are data, not protocol, and
we have not re-derived them.

> The brief referred to `BytesUtils.splitPackage` as the multi-packet scene
> path. It is not: `com.govee.encryp.BytesUtils.splitPackage` belongs to the
> **encryption** layer and implements the small-MTU `0xE719`/`0xE71A`
> fragmentation described in `PROTOCOL.md` §7. The scene path is
> `MultipleControllerCommV1.makeSendBytesV2`, documented in §5 here.

#### 2.3.6 Music and mic — sub-mode `0x13` (and family variants)

**verified for H66A0**; **from APK** for other families.

Reachable over BLE, but the payload is the most model-divergent part of the
whole protocol. The common shape is:

```
33 05 13 <music effect id> <sensitivity 0..99> [<auto-colour flag> RR GG BB]
```

Observed on the H66A0 (capture 2):

```
3305 13 05 63 00 01 ff        effect 5,  sensitivity 99
3305 13 03 63 00 00 00        effect 3,  sensitivity 99
3305 13 34 63 00 01 ff        effect 52, sensitivity 99
3305 13 34 3b 00 01 ff        effect 52, sensitivity 59
```

Effect `0x34` = 52 = `music_code_rgbic_gangqinjian` ("piano keys") in
`AbsNewMusicEffect`. The **palette and per-effect parameters are not in this
frame** — they are uploaded separately as a `0xA3` multi-packet write with
command type `0x41`; see §5.4. The bytes after `sensitivity` are the
auto-colour flag and a colour, but we only ever saw `00 01 ff` and `00 00 00`,
which is not enough to pin the field order, so it is left undecoded.

with per-family additions — `pact_tvlightv3`'s `SubModeMusicV3` emits a
different field order for effects 3, 5, 8 and 9 than for the rest. Some
families put music on `0x0c`, `0x0e`, `0x0f` or `0x11` instead.

We did not exercise music mode on hardware, and we are not documenting a
per-effect table we cannot check. If you need music mode on a specific SKU,
read that SKU's `SubModeMusic*` class.

Mic mode is likewise family-specific (`0x05` on H6185, `0xFF` on H6181, a
separate `MicController` elsewhere). `Beshelmek/govee_ble_lights` declares
`LedMode.MICROPHONE = 0x06` and `LedMode.SCENES = 0x05`; **neither matches the
base2light sub-mode numbering** (scenes are `0x04`), and neither constant is
actually used by that integration's code.

### 2.4 Colour temperature / white

There is **no separate colour-temperature command** in this protocol. Warm/cool
white is expressed inside the colour sub-mode:

* dialect `0x15`: `33 05 15 01 00 00 00 <kelvin BE16> <RGB of that kelvin> <segmask>` — **verified**
* dialect `0x0d`: `33 05 0d RR GG BB <kelvin BE16> <RGB of that kelvin>` — **from APK**
* dialect `0x02`: only a white on/off flag plus its RGB rendering — **from APK**

The app always sends *both* the Kelvin value and its RGB rendering. A client
that sends Kelvin with a zeroed RGB has not been tested; we do not know whether
firmware uses the RGB field as the actual output or only as a hint.

The H66A0's colour-temperature range is not carried on the wire anywhere we
found. `Config4ColorTemp` lists H66A0 among SKUs with a "Kelvin single
controller" UI, but the range itself comes from the cloud.

### 2.5 Segments

* **Per-segment colour and brightness are set** through colour dialect `0x15`
  types 1–3, or dialect `0x0b`, using the segment bitmask (§2.3.2, §2.3.4).
* **Per-segment state is read** with `0xA5` (§2.6).
* **Segment count** — see §3.3.

### 2.6 Queries (`0xAA`)

All **verified** unless marked. Payload offsets below are relative to the start
of the payload, i.e. byte 2 of the frame.

> **The bare-form trap — a query with a selector answers nothing without it, and
> that silence reads exactly like "the device does not support this".** This has
> now produced a false negative twice, on two different devices and two different
> opcodes, so it is a rule rather than an anecdote.
>
> * `aa ae` — the bare form answers `00 00`, which is where the long-standing
>   "reports zero relative-brightness zones" claim came from. With its `0x01`
>   selector an H66A0 answers four populated edges, and always had.
> * `aa 07` — the bare form draws total silence. On 2026-08-25 that was briefly
>   recorded as "H1A42 has no hardware version, so `OtaType.parseHardVersion` has
>   no input on this device". With the `0x03` selector this table already documents,
>   the same device answered `3.08.01` immediately.
>
> Both times the correct request was already written down here and the frame was
> sent without checking. So: **before concluding a device lacks a capability,
> re-read this table and confirm the request shape.** Treat silence from a query
> that takes a selector as *asked wrong* until the grammar has been checked;
> absence is only a finding once the request is known to be right.
>
> The converse also holds and is what makes this cheap to check: a device that
> answers other queries on the same connection is reachable, so an isolated silence
> is far more likely to be a malformed request than a missing feature.

| Cmd | Name | Request | Reply payload |
|---|---|---|---|
| `0x01` | power | — | `[0]` = 0/1 |
| `0x04` | brightness | — | `[0]` = level |
| `0x05` | mode | — | `[0]` = sub-mode, then sub-mode state (§2.3) |
| `0x06` | software version | — | ASCII, NUL-padded (`"1.00.21"`) |
| `0x07` | device info | `[0]` = selector | `[0]` = selector, `[1:]` = ASCII (`"3.07.01"`) |
| `0x09` | time | — | see §2.7 |
| `0x11` | sleep timer | — | `[0]`=enable `[1]`=`startBri` `[2]`=`closeTime` `[3]`=`curTime` `[4]`=`defaultLight` `[5:8]`=RGB |
| `0x12` | wake-up alarm | — | `[0]`=enable `[1]`=`endBri` `[2]`=`wakeHour` `[3]`=`wakeMin` `[4]`=`repeat` bitmap `[5]`=`wakeTime` `[6]`=`defaultLight` `[7:10]`=RGB |
| `0x14` | wifi MAC | — | `[0:6]` = MAC — **verified**, and confirmed to be the WiFi interface (§2.6.4) |
| `0x20` | wifi hardware version | — | ASCII — **verified** (`"6.01.00"`) |
| `0x21` | wifi software version | — | ASCII — **verified** (`"1.01.18"`) |
| `0x23` | timers | `[0]` = index, or `0xFF` for all | `[0]`=`0xFF`, then 4 × `{enable/type, hour, minute, repeat}` — read form now **verified** (see §2.6.1) |
| `0x40` | IC / segment count | — | `[0:2]` = IC count big-endian, `[2]` = segment count — **verified**, and the second field is new (see §3.3) |
| `0xA3` | gradual change | — | `[0]` = 0/1 — read as part of the segment snapshot, and written before a repaint; see §2.3.4 |
| `0xA5` | per-segment colour | `[0]` = page, 1-based | `[0]`=page, then 4 × `{brightness, R, G, B}` |
| `0xA9` | video / AI settings | `[0]` = sub-command | sub-command specific — see below |
| `0xAE` | relative brightness | `[0]` = sub-command | `[0]`=sub, `[1]`=zone count (4 or 6), `[2:]`=per-zone level |
| `0xEF` | protocol version | — | `[0:2]`=pactType big-endian, `[2]`=pactCode — **from APK** |

Field names for `0x11` and `0x12` are the app's own (`SleepInfo`, `WakeUpInfo`);
`closeTime`/`curTime`/`wakeTime` are minute counts but we have not confirmed
which is the fade duration and which the remaining time, so they are left named
rather than interpreted.

`0x07` device-info selectors (**from APK**): `2` = UUID, `3` = hardware version,
`4` = software version, `7` = DSP version, `11` = MCU hardware version. The
capture uses selector `3`. Note that `0x06` returns the software version
directly with no selector — the two overlap.

`0xA5` returns 4 segments per page and pads with zeros on the last page. Our
H66A0 answered pages 1–4 with 4+4+4+2 = **14** non-zero segments, matching the
`0x3FFF` mask. **verified**, and reproduced on 2026-08-23.

### 2.6.1 Replies observed on 2026-08-23 — **verified**

A read-only sweep of the H66A0 (firmware `1.00.21`, hardware `3.07.01`), camera
module absent. Payload bytes only; the leading `aa <cmd>` and the trailing XOR are
stripped. The WiFi MAC is a device identifier and is withheld.

| Query | Payload | Reading |
|---|---|---|
| `aa 01` | `01` | on |
| `aa 04` | `64` | 100 — a 0–100 device at full brightness, confirming §3.2 |
| `aa 05` | `00 00 08 32 00 02 64` | sub-mode `0x00` at rest; **not** a documented colour mode. The same device answers `0x15` after a colour write — see §3.4 |
| `aa 06` | `"1.00.21"` | software version |
| `aa 07 03` | `03 "3.07.01"` | hardware version |
| `aa 14` | 6 MAC bytes | WiFi MAC — module **attached** only, see below |
| `aa 20` | `"6.01.00"` | WiFi hardware version — module **attached** only, see below |
| `aa 21` | `"1.01.18"` | WiFi software version — module **attached** only, see below |
| `aa 23 ff` | `ff 01 03 02 83 · 00 00 00 80 · 00 00 00 80 · 00 00 00 80` | timer 1 set for 03:02, three empty slots — matches the documented 4×`{enable/type, hour, minute, repeat}` layout exactly |
| `aa 40` | `00 5a 0e` | 90 ICs, 14 segments — see §3.3 |
| `aa a3` | `00` | gradual change off |
| `aa ae` | `01 04 32 32 32 32` | **four** relative-brightness zones, all at 50 — see the correction below |
| `aa ef` | `00 02 01` | pactType 2, pactCode 1 — see §3.5 |
| `aa 11` | `00 3a 0f 0f 01 ff 00 6e` | sleep timer off; shape matches the documented layout |
| `aa 12` | `ff 64 00 00 80 0a 00 ff ae 54` | wake-up — **does not fit the documented layout**, see below |
| `aa 32` | `01 01` **with the module attached**; *no reply* without it | camera install check — see §2.6.3 |
| `aa a9 <sub>` | seven subs answer with the module attached; *no reply* without it | video/AI — see §2.6.3 |

Three honest corrections fall out of this, two of them added on 2026-08-24 after
capture 1 was swept frame by frame against this table.

**`aa ae` needs its selector byte, and the "zero zones" reading was the cost of
omitting it.** This is now settled on hardware, both ways in one session:

```
aa ae            ->  aa ae 00 00 …                 zero zones  (the old reading)
aa ae 01         ->  aa ae 01 04 32 32 32 32       four zones at 50
```

`0x01` is the selector the Govee app sends in capture 1, and the bare form is what
the earlier sweep sent. So the register was never empty; the query was
under-specified. `0xAE` joins `0x07`, `0x23`, `0xA5` and `0xA9` as a query whose
argument is not optional.

**And the write applies.** Driven on the device 2026-08-24 with the module
attached: `33 ae 01 04 3c 3c 3c 3c` read back as `01 04 3c 3c 3c 3c` (60), then
`… 32 32 32 32` restored it to the 50 it started at. So relative brightness is a
working, round-tripping control on the H66A0, not merely a populated register —
`supports_relative_brightness` was **false** for this model and that is a defect,
now corrected.

**The three WiFi rows are module-attached readings.** This section is headed
"camera module absent", but in capture 1 — module detached — `aa 14`, `aa 20` and
`aa 21` are asked as the first three frames of the session and **never answered**,
while `aa 06`, `aa 07`, `aa 23`, `aa 05`, `aa 04`, `aa 11`, `aa 12` and `aa 01`
all reply on that same connection. The values quoted above are real, but they came
from the run with the module fitted. That is consistent with the module carrying
the WiFi radio, and it means the WiFi identifiers and versions are **not** readable
on a bare H66A0.

**Confirmed both ways on 2026-08-24**: with the module attached, all three answer
on the same connection — `aa 20` -> `"6.01.00"`, `aa 21` -> `"1.01.18"`, and `aa 14`
returns six MAC bytes. So the rule is the accessory, not the protocol. This settles
a question left open in `INTEGRATION_NOTES_hippo.md` §2e: three of the four
`pact_tvlightv2` firmware gates need `wifiSw`/`wifiHw`, and on a camera-equipped
device those strings **are** readable, so those gates are evaluable after all.

**`aa 12` byte `[0]` is not a boolean.** The documented layout calls it `enable`,
but the device returned `0xFF`. Every other field in that reply is plausible
(`endBri`=100, `wakeHour`/`wakeMin`=0, `repeat`=`0x80`, `wakeTime`=10,
`defaultLight`=0, RGB=`ff ae 54`), so this is one field being wrong rather than the
whole layout. We do not know what `0xFF` means here; it is left as an open question
rather than reinterpreted to fit. The `0x11` sleep-timer reply has no such problem.

**`aa 32` and `aa a9` silence on that run was the detached module, and the
follow-up settled it.** With the module attached the whole surface answers
(§2.6.3). With it detached, `aa 32` and every `aa a9` sub go silent while `aa 40`,
`aa 01`, `aa 04`, `aa 06` and `aa 07` reply on the same connection — re-confirmed
2026-08-24, and bursting was ruled out by pacing the queries a second apart. So
the *arrival* of `aa 32` is the install signal, and its absence is the accessory,
not the protocol.

Two sub-commands are the exception and never answer either way: see the
sync-box box in §2.6.

### 2.6.2 Writes driven on hardware, 2026-08-23 — **verified**

Sent over an encrypted session and confirmed by reading the state back, so each of
these is a round trip rather than a frame that was merely accepted.

| Write | Read back with | Result |
|---|---|---|
| `33 01 00` / `33 01 01` | `aa 01` | power off and on |
| `33 04 25` (37) | `aa 04` | reported `0x25` — **0–100 scale settled for this model** |
| `33 04 50` (80) | `aa 04` | reported `0x50` |
| `33 05 15 01 <rgb> … <mask 0x3FFF>` | `aa a5 01` | all four segments on page 1 took the colour, for blue, green and red |
| `33 05 15 01 <rgb> … <mask 0x7FFF>` | `aa a5 01` | **accepted on a 14-segment device**: the two mask bits above segment 14 are ignored rather than rejected, so a client that hardcodes `0x7FFF` for "all segments" still works here |
| `33 05 15 02 <pct> <mask>` | `aa a5 01` | per-segment brightness applied to the addressed range |

**The device pushes `0xEE30` on its own.** Toggling power produced
`ee 30 01 00 00 00 …` and `ee 30 01 01 01 00 …` unprompted, ahead of the polled
`aa 01` reply. Confirms §4's `0xEE30` type 1 on this model, and means a client can
follow state changes made from the Govee app without polling for them.

`0xA9` sub-commands (**from APK**, from the controller classes that build them).
Writes take the form `33 A9 <sub> <count> <values...>`; reads are a bare
`AA A9 <sub>`.

| Sub | Meaning | Builder | On H66A0 |
|---|---|---|---|
| `0x01` | video sensitivity | `VideoSensitivityController` | reads `50`; accepts a write and does not apply it |
| `0x03` | HDMI source | `Controller4Hdmi` | **never replies, camera attached or not** — see below |
| `0x04` | AI action / AI switch | `AiActionController` | reads 7 bytes |
| `0x05` | colour calibration | `ColorCaliController` | not touched — calibration |
| `0x06` | white balance | `Controller4WhiteBalance` | not touched — calibration |
| `0x08` | AI model | | never replies |
| `0x09` | AI update status | `AiUpdateStatusController` | reads 1 byte |
| `0x0A` | black-screen detection | | reads 6 bytes |
| `0x0B` | black-border removal | `BlackBorderRemoveController` | **read + write round-tripped** |
| `0x0C` | black-screen HDMI | | never replies |
| `0x0D` | HDR calibration | `HDRCaliController` | not touched — calibration |
| `0x0E` | video saturation | `VideoSaturationController` | **never replies, camera attached or not** — see below |
| `0x10` | AI filter | `AiFilterController` | reads 15 bytes |
| `0x11` | HDR effect ("HDR Contrast") | `VideoHdrEffectController` | `{17, 2, enabled, level}`; both bytes named — see §2.6.3a |
| `0x12` | auto white balance (set) | `VideoAutoWbController` `{18, 1, v}` | not touched — calibration |
| `0x13` | check WB calibration | `VideoCheckWbCaliController` | not touched — calibration |
| `0x14` | auto white balance (run) | `VideoAutoWbController` `{20}` | not touched — calibration |

> #### `0x03` and `0x0e` belong to the HDMI sync-box sibling — **from APK**
>
> An earlier draft of this document implied Govee ships sub-commands nothing
> supports. That was wrong. Govee sells an **HDMI sync-box variant** in this
> product line, the app is a single binary serving the whole family, and these two
> sub-commands are that sibling's. An HDMI source selector and a saturation slider
> are exactly what a sync box needs and exactly what a camera-based backlight does
> not have.
>
> This is **from APK**, not inferred, and the chain is short:
>
> * `Controller4Hdmi` (sub `0x03`) is constructed in exactly one place:
>   `com.govee.pact_h605b.newdetailhdmi.viewmodel.NewDetailHdmiVm`.
> * `VideoSaturationController` (sub `0x0e`) likewise — its only construction site
>   outside its own class is the same `NewDetailHdmiVm`. The generic video sheet
>   asks its view model `supportSaturation()`, and the base implementation
>   `AbsVideoNewDetailVm.supportSaturation()` **returns `false`**. Only
>   `pact_h605b.newdetailhdmi.viewmodel.VideoVmHdmi` overrides it, with
>   `Support.supportHDR(...)`.
> * Which screen a device gets is decided by `Support.isHdmiSku(goodsType)`, and
>   the app branches the whole detail activity on it —
>   `NewDetailHdmiAc` versus `NewDetailAc` (`AbsActivity4Add`, `SwapLightAc`,
>   `WifiChooseAc`).
>
> The first two points are the load-bearing ones, and they are **app-wide, not
> family-local**: the base video sheet returns `false` for saturation, so *no*
> product family in this binary offers it except the HDMI screen. That matters
> because the H66A0 is not in `pact_h605b` at all — the string `"H66A0"` appears
> nowhere in any pact package (§3.5a), so `isHdmiSku`'s SKU list is its siblings'
> rule rather than a statement about our device. Our device is excluded from these
> two sub-commands by never reaching the HDMI view model, whichever pact serves it.
>
> ```java
> // com.govee.pact_h605b.pact.Support
> isHdmiSku(gt) = isGoodsTypeH6601(gt) || isGoodsTypeH6602(gt)
>              || isGoodsTypeH6603(gt) || isGoodsTypeH6604(gt);
> // goodsType: H6601 = 138, H6602 = 142, H6603 = 192, H6604 = 243
> ```
>
> So the accurate claim is **"not supported on H66A0 (the camera variant); belongs
> to the HDMI sync-box variant of the same family (H6601–H6604)"**. The observed
> silence is **verified** independently: the H66A0 never answers `0x03` or `0x0e`
> with the camera module attached *or* detached, which rules out "the accessory is
> missing" and is what separates these two from the rest of the table.
>
> **The gate is NOT readable at runtime, and that is the disappointing part.** It
> keys off `goodsType`, which is a **cloud** field (§3.2 already says so for the
> brightness scale). It is *not* `pactType`/`pactCode` — those are readable three
> ways over BLE (§3.5) and are not consulted here — and there is no capability
> query for it anywhere in the protocol (§3.5a). A client that wants to distinguish
> the variants without the cloud has only the SKU in the advertised local name
> (`Govee_H66A0_xxxx`) or, more honestly, the device's own silence.
>
> Practical consequence: **availability-gate these, do not delete them.** A
> sync-box owner should get them; an H66A0 owner should not see a dead control.
> `teh-hippo/ha-govee-led-ble` does exactly that — the sub-commands stay in the
> table and in the read set, and the entities behind them go unavailable.

### 2.6.3 The `0xA9` surface with the camera module attached — **verified**

Read on 2026-08-23 with the module fitted, and re-swept on 2026-08-24 with six
sub-commands that had never been asked. **Ten registers answer, not seven.** The
three additions are read-only observations; `0x06`, `0x12` and `0x13` are all on
the calibration *write* exclusion list and that is unchanged — reading a register
is not writing it. Payload bytes only. Lengths are the
register's own `len` field and each agreed with the bytes that followed it, which
is what confirms the `setting`/`len`/`values` shape from the wire rather than from
the H6199's spec.

| Sub | Len | Value | Reading |
|---|---|---|---|
| `0x01` | 1 | `32` | video sensitivity = 50. Accepts a write and does **not** apply it |
| `0x04` | 7 | `00 00 00 00 00 04 00` | AI action. Not decoded — 7 bytes, one observation |
| `0x09` | 1 | `00` | AI update status |
| `0x0A` | 6 | `00 01 0a 00 58 02` | black-screen detection. Not decoded |
| `0x0B` | 1 | `01` | black-border removal **on**. Write round-tripped and restored |
| `0x10` | 15 | all zero | AI filter. Not decoded |
| `0x11` | 2 | `01 02` | HDR effect: **enabled**, **gear 2 of 4**. See §2.6.3a |
| `0x06` | 1 | `32` | **white balance = 50.** Added 2026-08-24; never asked before |
| `0x12` | 1 | `01` | auto white balance. Added 2026-08-24 |
| `0x13` | 1 | `01` | check WB calibration. Added 2026-08-24 |
| `0x03`, `0x05`, `0x08`, `0x0C`, `0x0D`, `0x0E`, `0x14` | — | *no reply* | see below |

`aa 32` answered `01 01`. The two bytes are left unnamed: one observation cannot
separate them, and the arrival of the frame is the signal we actually use.

> **`aa 32` cannot be used as a presence check, and this is a trap worth naming.**
> It is the *camera install check*, so the obvious design is to ask it and branch on
> the answer. That cannot work: `aa 32` is **itself camera-gated**. With the module
> unplugged it goes silent alongside every register it would tell you about, so a
> client that waits for its reply learns nothing and cannot distinguish "no camera"
> from "no device".
>
> The signal is not a reply — it is the **pattern**: every camera register silent
> *while non-camera registers answer on the same connection*. That is a positive
> determination of absence, and it is exact. Measured 2026-08-24 across five query
> shapes (back-to-back, 250 ms spacing, 1 s spacing, a link warmed for 12 s, and
> warmed plus 1 s spacing): **6/16 answered every time, the same ten silent, and
> position-independent** — `aa 32` stayed silent even when sent as the second frame
> of the burst. `aa 40`, `aa a5` and `aa a3` answered throughout.
>
> Distinguish three outcomes, not two. A camera register answered ⇒ present. None
> did but something else did ⇒ **absent**. Nothing answered at all ⇒ the device is
> unreachable, and nothing about the camera has been established.

#### The four silent sub-commands, all four explained — **from APK**, 2026-08-24

`0x03` and `0x0E` were settled earlier: they belong to the HDMI sync-box variant
(§2.6). The remaining two were recorded as "unexplained". They are not, and both
answers have the same shape as the `0x11` decode — the class's own construction
sites, not a plausible story about them.

* **`0x0C` — `BlackScreenHdmiController`**, in package
  `com.govee.base2light.balckscreen.hdmi.controller` (Govee's typo, not ours). Its
  read is issued from `AbsVideoNewDetailVm` behind a gate `H()`, which **returns
  `false` in the base class and is overridden nowhere in the APK**. That is a
  stronger result than `supportSaturation()`, which at least one view model
  overrides: nothing in the shipped app ever turns this register on. Silence is
  the only behaviour any device could show us.
* **`0x08` — `AiIdentifyModelController` / `ChangeAiModelController`.** Both have a
  single constructor and it calls `super(true)`; `AbsController.isWrite()` returns
  that flag, and the sibling `BlackScreenHdmiController` demonstrates the pattern
  by having *two* constructors, `()` for a read and `(bean)` for a write. `0x08`
  has no read form, so the app never sends `aa a9 08` — the register may well
  exist, but a read of it is not a question this protocol asks.

`0x05` falls to the same argument as `0x0C`: colour calibration is issued behind
`AbsVideoNewDetailVm.I()`, which is `false` in the base class and overridden only
by `VideoVmHdmi`. `0x0D` and `0x14` are the remaining calibration entry points and
behave like `0x08` — the app constructs them to write, never to read.

So of the seven `0xA9` sub-commands this camera does not answer, **not one
indicates a missing accessory or a firmware shortfall**: five are structurally
unreachable from any view model the app ships, and two have no read form at all.

**And `0x06` is the one that changed a claim.** It answers `01 32` — one byte,
value 50 — on a device whose profile said it had no white balance. That is exactly
what the APK predicted: `WhiteBalanceDialog` lists H66A0 in the SKU array that
selects the 0-100 progress type and resets to **50**. A UI list is weak evidence
on its own; a UI list that predicts the register's value is not.

**Which of these three may be READ, and the one that may not.** A read cannot
overwrite calibration — `aa a9 06` carries no value, and the write form
`33 a9 06 01 <v>` is a different frame — so the question is only whether the
register has a *get* form at all. The bar is the one that settled `0x11`:

| Sub | Verdict | Why |
|---|---|---|
| `0x13` | **getter** | `VideoCheckWbCaliController.makeReadController()` = `(false, {19})` — `isWrite` false, bare sub-command, no argument — plus `parse(bArr) -> bArr[2] == 1` |
| `0x06` | **getter** | `Controller4WhiteBalance` writes `{6, 1, v}`; `parse(bArr) -> bArr[2]` reads the same position, and `01 32` decodes through it to 50 |
| `0x12` | **not proven** | `VideoAutoWbController` has only `makeWriteController(v)` and `makeExitCaliController()`, both `isWrite = true`; no read factory, no parser |

So `0x13`, whose name suggests it might *run* a calibration pass, is the
best-evidenced getter of the three, and `0x12`, which looks like an obvious one,
has no evidence at all. **Answering is not evidence of being a getter.**

#### `0x11` decoded — **from APK**, corrected 2026-08-24

An earlier version of this section said the two bytes could not be named. That was
true of the evidence then available and is no longer true.
`VideoHdrEffectController` is **symmetric** — it builds the write and parses the
read with the same field order — which is what turns a plausible reading into a
determination:

```java
// com.govee.base2light.videomode.newdetail.controller.VideoHdrEffectController
write : new byte[]{17, 2, bean.b(), (byte) bean.a()}   // {sub, len, enabled, level}
parse : new HDREffectBean(bArr[2] == 1, bArr[3])       // {enabled, level}

// com.govee.base2light.videomode.newdetail.bean.HDREffectBean
HDREffectBean(boolean enabled, int level)
```

So the write form is:

```
33 A9 11 02 <enabled 0|1> <level>
```

**verified against the wire**: our H66A0 answered `aa a9 11 02 01 02` →
`enabled = true, level = 2`.

**The level's range is still open.** `HDRContrastViewInterface` defaults an unset
bean to `new HDREffectBean(false, 50)`, which hints at 0–100 like every other
percentage on this surface — **inferred**, from a default value, not a bound.

And a curiosity worth recording: **no shipped Govee SKU exposes this control.**
`AbsVideoNewDetailVm.supportHDRContrast()` returns `false` and nothing in the app
overrides it (contrast `supportSaturation`, which `VideoVmHdmi` does override). The
register answers reads on our hardware regardless. `teh-hippo/ha-govee-led-ble`
therefore decodes and reports it and still ships no control — a writer here would
be the first anywhere, at an unverified range.

### 2.7 Time — `0x09` — **verified**

```
33 09 <hour> <minute> <second> <weekday> 01 <tz hours> <tz minutes>
```

`weekday` is 1 = Monday … 7 = Sunday. Byte 4 is a constant `0x01`. The capture
shows `3309 17 02 04 02 01 01 00` = 23:02:04, Tuesday, UTC+1:00.

`ControllerSyncTime` has a longer variant that appends day, month, a 16-bit
year and a 32-bit epoch — **from APK**, not seen here.

### 2.8 Other commands in the common set — **from APK**

Read from the controller classes; none exercised on hardware.

| Cmd | Name | Payload |
|---|---|---|
| `0x0A` | auto-time / schedule | `{enable, startH, startM, endH, endM, index, flags}` |
| `0x0B` | delay close | `{enable, hours, minutes}` |
| `0x0F` | segment / bulb count setting | family-specific |
| `0x13` | night mode | |
| `0x16` | energy saving **or** status-light indicator | ambiguous: `EnergySavingController` sends `{0|1}`, `LightIndicatorController` sends `{enable, startH, startM, endH, endM}` with `FF FF FF FF` meaning "always". Two different features share the byte; which one applies is a per-family question we have not resolved. |
| `0x23` | timer (write) | `{index, enable/type, hour, minute, repeat}` — **verified**, capture 2 |
| `0x30` | light switch (sub-light) | |
| `0x33` | volume | |
| `0x37` | prompt tone | |
| `0x40` | IC / segment count | read-only in practice |
| `0x41` | on/off memory | |
| `0xEE` | OTA prepare | |

The full constant table is `BleProtocolConstants` in
`com.govee.base2light.ble.controller`; it names roughly 150 commands, most of
them for device families far outside this document's scope.

---

### 2.9 Mic — the `0xA5` frame family — **verified**

> **Why there is no "music input source" command — inferred, 2026-08-25.** The app offers a
> choice between using the phone's microphone and the light's own, and a search for an opcode
> carrying it found nothing: not in either capture, not in the APK.
>
> The likely answer is that it is not an opcode at all. **It is which frame family the app
> uses.** Device-microphone music is `33 05 13` with a mode and sensitivity — the light listens
> for itself. Phone-microphone music is *this* `0xA5` family: the phone samples audio and
> streams it to the light, which renders what it is sent rather than listening.
>
> If that is right, "method" is a property of the client, not a device setting, and there is
> nothing to read back — which is exactly consistent with having found no field for it. It
> also means a local integration implementing only `33 05 13` gets device-microphone music and
> can never offer the phone option, because the phone option requires a live audio stream from
> whatever is driving the light.
>
> Marked **inferred**. It rests on the absence of a command plus the existence of a streaming
> family that would make one unnecessary, and neither half has been confirmed by watching the
> app switch the setting.

`AbsMicController` is the one controller in this document that does not build a
20-byte frame. Its two forms are:

```
read    a5 02 <command> <sum>
write   a5 02 <command> <payload...> <sum>
```

* byte 0 is the proType `0xA5`, byte 1 is a constant `0x02`
* the length is `len(payload) + 4` — **variable, never padded**
* the last byte is `BleUtils.getByteSum()`: the 8-bit **sum** of every preceding
  byte, *not* the XOR that every other frame uses

| Command | Controller | Payload |
|---|---|---|
| `0x83` | `MicSetRgbController` | `RR GG BB` |
| `0x05` | `MicController` | family-specific |
| `0x90` | `MicColorCmdController` | — it overrides `g()` to send its bytes raw, so it does *not* take the `a5 02` wrapper |

**verified** — capture 2 contains exactly one, at host counter `0x4c`:

```
a5 02 83 ff 69 00 92
│  │  │  └──────┘ └── sum: (a5+02+83+ff+69+00) & 0xff = 0x92
│  │  └───────────── 0x83 = MicSetRgbController
│  └──────────────── constant
└─────────────────── proType 0xA5
```

so: **mic set RGB = `#ff6900`**. Every field checks out — proType, command byte,
payload length and checksum — which is what makes this an identification rather
than a plausible reading.

It arrives mid-way through a burst of colour-wheel drags, carrying the same RGB
as the `33 05 15 01` colour frame that immediately follows it. The likely reading
is a stray callback from the app's "mic by phone" UI path
(`AbsMicByPhoneUiMode`), which pushes RGB in real time and would emit one of
these per colour change; only one appears in 1022 frames, so it is not part of
the normal colour path. **Why the app emitted exactly one is not established** —
that part is inference, and it is separable from the frame decode above, which
is not.

---

### 2.6.3a `0xa9` sub `0x11` — HDR contrast is a 4-gear scale, and the app never shows it

**from APK, 2026-08-25.** This register was previously written up here as "write round-tripped,
meaning unknown", which was stale — a commit in the integration had already decoded both bytes.
The full picture:

```
com.govee.base2light.videomode.newdetail.controller.VideoHdrEffectController
    write:  new byte[]{17, 2, bean.b(), (byte) bean.a()}   ->  33 a9 11 02 <enabled> <gear>
    read :  HDREffectBean(bArr[2] == 1, bArr[3])           ->  enabled, gear
```

So it is **an enable plus a level**, not a toggle. The level is a **discrete gear, not a
percentage**: the control is a `VideoTextSpiltPointView` wrapping a `SpiltPointViewV2`, and the
layout `b2light_video_text_spilt_point` fixes its size:

```
app:spiltPoint_nums="4"              four positions
app:spiltPoint_choosePointPos="1"    position 1 is the default
setSpecialPos(1)                     position 1 is also drawn as the "recommended" gear
```

`onPositionChange(int i)` writes the position straight through (`bean.c(i)`, then
`(byte) bean.a()`), so the **wire value is the gear index: 0–3**. An H66A0 answering `01 02`
is enabled at gear 2. The app's own analytics label is `click_HDR_gear_<i>`, which is the
vendor calling them gears too.

> **But the vendor app never exposes this control.** The gate is
> `HDRContrastVmInterface.supportHDRContrast()`, and `AbsVideoNewDetailVm` returns **false**
> — with **no override anywhere in the decompiled tree**. This is the same base-versus-override
> pattern that settled `0x03` and `0x0e` (§2.6.3), except here nothing turns it on at all.
>
> The register is nonetheless live: an H66A0 answers the read and accepts a write. So a local
> client *can* drive an axis the app itself keeps hidden — which is a reason to document it
> carefully and a reason **not** to ship it as a control without deciding that deliberately.
>
> **Checked properly, and the picture does not close.** The gate was traced end to end rather
> than from a single grep:
>
> * The HDR **contrast** view is `AbsVideoMode.z0()`. It is **added by no subclass** in either
>   version — `pact_h605b`'s `VideoMode.D1()`/`E1()`, `VideoModeH2A40`, `HdmiVideoMode`,
>   `pact_tvlightv2`, `pact_tvlightv4`, `h604a` and `h6104` were all checked.
> * `supportHDRContrast()` returns `false` in `AbsVideoNewDetailVm` in **7.5.30 and 7.6.10**,
>   overridden nowhere in either.
> * HDR **calibration** is a different feature on a different register (`0xa9` sub `0x0d`,
>   `HDRCaliController`). It *is* wired up — in `HdmiVideoMode`, gated on
>   `VideoVmHdmi.supportHDRCali()` → `Support.supportHDR()`, which returns true **only for
>   goodsType H6603/H6604** (the HDMI sync boxes) above specific firmware versions.
>
> **This contradicts observed reality**, and the contradiction is recorded rather than
> explained away: the owner sees HDR controls in the Govee app on an H66A0, and the H66A0
> answers `aa a9 11` with `01 02`. Both static paths above say it should not be offered on
> that model. So one of the premises is wrong — most likely the long-held assumption that the
> H66A0 is served by `pact_h605b`, which this project inherited without ever verifying it.
>
> **Do not treat the "app never shows it" reading as settled.** It is a prediction that the
> hardware has already falsified — the owner confirmed a **four-dot picker** in the app on an
> H66A0 on 2026-08-25, which is this control and confirms `spiltPoint_nums="4"` from the other
> side.
>
> **A stale premise found while chasing it, and it is load-bearing well beyond HDR:**
> `com.govee.pact_h605b` **does not exist in 7.6.10**. The pact packages in the current build
> are `pact_tvlightv2`, `pact_tvlightv3`, `pact_tvlightv4` and `pact_rgblight`. Every statement
> in this document that reasons from "the H66A0 is served by `pact_h605b`" — including the
> `Controller4Hdmi` / `VideoSaturationController` exclusion in §2.6.3 — is therefore a claim
> about **7.5.30 only**, and the H66A0's pact package has since moved. That premise has been
> carried through this project without ever being verified, and it is the most likely reason
> the gate cannot be located.
>
> **None of this blocks a client.** The gate decides what *Govee's app* shows. What a local
> client needs is the write form (known), the range (known, and confirmed by eye) and that the
> device answers (it does). The open question is the app's UI logic, not the protocol.

> **HDR gear range corrected 2026-08-27: it is 1–4, not 0–3.** A device whose app showed the
> fourth circle answered `aa a9 11` with `02 01 04`; the second answered `02 01 02`. The 0–3
> reading was inferred from the widget's `spiltPoint_nums="4"` and would have refused gear 4.

### 2.6.3b Video mode is `33 05 00`, and its body is per-model — **from APK, 2026-08-25**

Video mode ("DreamView") is not a separate opcode. It is a **`33 05` sub-mode like scene,
music and DIY**, and its selector is **`0x00`**:

```
AbsVideoNewDetailVm.B(params)  ->  Controller4ExtBytes.e( [0x05] + body )   ->  33 05 00 …
```

`B()` is **abstract**, so the body is defined per pact by whichever subclass implements it —
this is why there is no single "video mode frame". `com.govee.pact_h605b.newdetail.viewmodel.VideoVm`
(the H66A0's own pact) picks between three bodies on `goodsType`:

| Builder | Selected when | Body |
|---|---|---|
| `O()` | `Support.isGoodsTypeH605BOrH605D` | `00 <f> <e> <d> <b> <g> <h>` |
| `N()` | `Support.isGoodsTypeH2A40` | `00 <b> <d> <e> <f> 02 <g>` |
| `P()` | everything else | `00 <d> <b> <e> <f> <g> 00 <rb×4> 00` |

The fields come from `VideoModeControllerParams` (three integers defaulting to 50, a boolean,
and a `RelativeBrightnessBean` of four segment values). Which accessor is saturation, which is
sensitivity and which is the picture profile is **not** established from names alone — the
H6199's equivalent body has `game_mode` and `full_screen` at a polarity opposite to the order
the app lists them in (§2.4), which is exactly the kind of thing that only a capture settles.

> **Consequences worth stating plainly.**
>
> 1. **The H66A0 does have video mode.** Its pact ships a `VideoVm`. An earlier reading here
>    concluded otherwise from a capture that showed sub-modes `04`, `0a`, `13` and `15` and no
>    video — but the video selector is `00`, so that capture simply never exercised it. Absence
>    in one capture is not absence.
> 2. **It is not implementable yet.** Which of the three bodies an H66A0 takes depends on its
>    `goodsType`, which is a cloud field, and no captured H66A0 video-mode frame exists to
>    validate a builder against. This repository's bar is that a builder reproduces captured
>    frames byte for byte; nothing here can meet that today.
> 3. **One capture would settle all of it** — the body variant and every field's meaning — by
>    driving video mode in the app while recording.

### 2.6.3c DreamView group mode — what it does to BLE — **verified 2026-08-25**

DreamView is Govee's screen-sync feature. One device is the **Sync Center** (the vendor's own
term) and up to five others join as sub-devices; only a DreamView product can be the Sync
Center, and the hardware version must be above V3.00.01. The feature **requires BLE** — Govee
excludes the H6003 from it specifically because that model is WiFi-only.

That last fact is the one that matters here, and it was confirmed on hardware:

**The Sync Center drives its sub-devices over BLE itself.** With a group active, the two
sub-devices stopped advertising entirely and were absent from BlueZ, while 31 unrelated
devices were seen in the same second. Killing the vendor app freed **only the master** — the
sub-devices stayed dark, because their links are held by the Sync Center, not by the phone.

| | Sync Center (master) | Sub-device |
|---|---|---|
| Advertising while grouped | **yes** | **no** |
| Reachable by another BLE central | **yes** | **no** |
| Effect of killing the vendor app | becomes reachable | still unreachable |

**The master answers everything while grouped.** A 16-query read-only sweep of an H66A0 in an
active DreamView group answered **16/16**, including `aa 32` camera presence, every `0xa9`
video register, `aa 05`, `aa 40` and `aa a5`. **Writes apply too**: black-border removal was
written off, read back as off, and restored — a full round trip, in group mode.

So group membership does not restrict the master's protocol surface at all. What it restricts
is the **sub-devices**, absolutely, by occupying their single BLE link.

> **Consequence for any local integration.** A device that is a DreamView *sub-device* cannot
> be controlled by Home Assistant at the same time — not as a limitation of the integration
> but of BLE, since a peripheral accepts one central. The master is unaffected. This is worth
> saying plainly in a README, because the symptom (a light that is permanently `unavailable`
> while its neighbours work) looks exactly like a bug.

### 2.6.3d `0xa9` sub `0x11` — HDR verified on hardware

**verified 2026-08-25**, on an H66A0 in video mode with the camera attached:

```
write:  33 a9 11 02 <enabled> <gear>
read :  aa a9 11        ->  a9 11 02 <enabled> <gear>
```

Round-tripped rather than acknowledged: gear 1 written and read back as `02 01 01`, gear 3
written and read back as `02 01 03`, then restored to the device's original `02 01 02`. The
gear range agrees with the vendor UI's `spiltPoint_nums="4"`, so **0–3**.

Two practical notes, both learned the hard way:

* **Every `0xa9` write is acknowledged with a generic `33 a9 00`**, which echoes neither the
  sub-command nor the value. It means "accepted", not "applied", and it is identical for a
  write that lands and one that does not. Only a read-back distinguishes them.
* **Do not read the register back on the same connection immediately after writing it.** Doing
  so returned silence three times in a row and looked exactly like a rejected write. The same
  writes, re-read on a fresh connection, had all applied correctly.

### 2.11 Video mode on the H66A0 — the real body — **verified 2026-08-26**

From a capture of the vendor app pressing **"Start to Experience"** and then moving every
control (`tv_start_video_and_change_settings.pklg`, 84 writes, decrypted in full).

```
write:  33 05 00 <f0> <f1> <f2> <f3> <f4> <f5>
read :  aa 05    ->  05 00 <f0> <f1> <f2> <f3> <f4> <f5>
```

**Six body bytes, not twelve.** An earlier prediction here derived the body from
`pact_h605b`'s `VideoVm.P()` — twelve bytes including a four-slot relative-brightness block —
by way of the H66A0's `goodsType` 327. That prediction is **wrong**, and the reason is worth
recording: `com.govee.pact_h605b` **does not exist** in the app version that produced this
capture, so its `O()/N()/P()` selection never ran. Reading a builder out of a package that no
longer serves the device produced a confident, wrong answer; the capture settles it.

Every field is named, from the capture plus three labelled read-backs on 2026-08-27 where the
owner reported the app's state and the device was read immediately after.

| Byte | Field | Evidence |
|---|---|---|
| `f0` | **game_mode** | `01` while the app showed **Game**; the capture's `00`→`01` is Movie→Game |
| `f1` | **picture_preset**, `0x08 \| index` | `0x08` on **Solid**, `0x0b` on **Delicate**; app order is Solid, Vivid, Smooth, Delicate, and the capture stepped `08 09 0a 0b`. **Bit 3 is required** — see below |
| `f2` | **saturation**, 0–100 | `0x3e` = 62 against a slider reading **62%** |
| `f3` | **sound effects**, 0/1 | `01` with the toggle on; in the capture it went `0`→`1`, softness moved four times, then back |
| `f4` | **sound-effect softness**, 0–100 | `0x02` while the owner described softness as **"very low"**. `pact_tvlightv4` sets it from `SoundEffectViewInterface.onSoftnessChange` |
| `f5` | **whole relative brightness**, 0–100 | `0x01` while the owner reported relative brightness **1%**; `0x36` = 54 while they described "a slider … currently set to 50%, but no sides are toggled". The **per-side** values are a separate command, `0xae` |

Read and write share the layout: `aa 05` in video mode answers `00` followed by the same six
bytes, so a client can read the device's configuration and reproduce it exactly.

**Bit 3 of the preset byte is not decorative — it is tested by direct experiment.** Written with
that bit cleared (`0x09` → `0x01`), the device **accepted and stored** the value: a read-back
returned `0x01`, not a silently re-added `0x09`. But the vendor app then showed **none of the
four presets selected**, and the owner reported no other visible change. So the app matches the
whole byte against its four values `08 09 0a 0b` and treats anything else as "not one of mine".

Encode it as `0x08 | index`. Writing a bare index produces a state the device holds and the app
cannot represent.

**`f4` and `f5` were the other way round in this file until 2026-08-27, and the correction is
worth reading — three successive claims about `f4` were wrong.** It is `0x02` in every frame the
vendor app sends, which first earned it "reserved constant". A four-point probe then found
`0xFF` refused and this file claimed a firmware-validated 0–3 field — also wrong. A proper scan
accepted **4, 5, 6, 7, 8, 10, 16, 32, 64, 100, 127, 128 and 200**: every value tried except
`0xFF`, which the device refuses while keeping its previous value, so `0xFF` is a "no change"
sentinel and not a bound.

The naming was then settled from the APK, in bytecode rather than decompiler output. An earlier
revision of this file guessed that jadx had mangled the single-letter accessors. **It had not** —
`baksmali` disassembly shows `g()` reads field `f`, `o(I)` writes field `f`, `i()` reads field
`h`, `q(I)` writes field `h`, exactly as decompiled. The guess was speculation presented as a
conclusion, and it was wrong.

What the bytecode actually shows is that **the H66A0 is `pact_tvlightv4`**, and the two setters
belong to different sliders:

- `VideoVm.O()` builds `{0, d(), b(), e(), f(), g(), i()}` — so `g()` lands at `f4`, `i()` at `f5`.
- `Info4Detail.g0()` parses the reply back with `byte[4]→o()` and `byte[5]→q()`.
- `o()`/`g()` share field `f`; `i()`/`q()` share field `h`. Writer and parser agree slot for slot.
- `SoundEffectViewInterface.onSoftnessChange → o()` → `f4`. **`f4` is softness.**
- `WholeRLBrightnessViewInterface → changeWholeRlBrightness → q()` → `f5`.

The observation that had pointed the other way — "softness moved `f5` four times in the capture"
— was a misreading of which slider was moved. `onSoftnessChanged` is the **generic callback name
of the shared slider widget**, used verbatim by `SaturationViewInterface`,
`SensitivityViewInterface` *and* `WholeRLBrightnessViewInterface`. It is not a semantic label.
The slider moved in that capture was whole relative brightness, which sits on the same sheet.

Two independent read-backs confirm the corrected naming, both from the owner describing the
screen while the device was read:

- `aa 05` → `00 01 08 3e 01 **02** **01**` while the app showed sound effects on with **softness
  "very low"** (`f4` = 2) and **relative brightness 1%** (`f5` = 1).
- `f5` = `0x36` = 54 while the owner described a relative-brightness slider **"currently set to
  50%"** that was not being applied to any side.

`f4` never moved in any capture simply because **nothing in `pact_tvlightv4` writes `o()`** apart
from the parser — the only UI caller of either setter is `changeWholeRlBrightness`. That is also
why probing `f4` produced no visible effect: on this firmware it is stored, not acted on, unless
the sound-effect slider drives it.

**Identifying the pact.** Three pacts build a `33 05` video body and they are not
interchangeable — `h6104` builds **four** bytes (`{0, 0, d(), e()}`: game mode and saturation
only), while `pact_tvlightv2` and `pact_tvlightv4` build six. The two six-byte forms differ in
slot 1: tvlightv2's `SubModeVideo.getWriteBytes` puts a **boolean** there, tvlightv4 puts the
picture-preset byte. **The H66A0 sends `0x08` in slot 1**, which rules out tvlightv2. There are
exactly three `AbsVideoNewDetailVm` subclasses in the whole APK — confirmed by disassembling
every dex that references the base class and matching on `.super`, not by name search — so the
elimination is complete rather than merely unrefuted.

> **Video mode and DreamView are different modes.** A device in a DreamView group is *not* in
> video mode — its `aa 05` reports whatever mode it is actually in. Both screens offer their own
> Game/Movie, brightness, sound effects and saturation, but DreamView's live in the `0x60`
> family (§2.12) and video mode's live here. Conflating them cost this project several sessions.

### 2.12 `0x60` — DreamView ("Feast") — **from APK + verified**, not implemented

DreamView is called **"Feast"** internally, which is the key that unlocks it: the controllers
live in `com.govee.home.main.device.moment.feastcontroller` and
`…moment.moviefeast.ble.controllerV2`, and every one extends `AbsSingleFeastController`, whose
`u()` returns **`(byte) 96` = `0x60`**. Its matcher is
`getProType() == bArr[0] && u() == bArr[1] && getCommandType() == bArr[2]`, so every frame is

```
<33 write | aa read>  60  <sub>  <payload…>
```

**The complete sub-command set**, each named from its controller class and cross-checked
against a capture of the vendor app creating, configuring, toggling and deleting a group:

| Sub | Controller | Payload | Meaning |
|---|---|---|---|
| `01` | `MovieOpenControllerV2` | `{on, 1}` | **DreamView on / off** |
| `02` | `MusicModeControllerV2` | — | music mode |
| `03` | `FeastBrightnessController` / `MovieBrightnessController` | `{level, index}` | **per-device brightness** |
| `04` | `FeastBrightnessUniteController` | `{on}` | **Same Brightness** — one level for all, instead of per-device |
| `05` | `SubDeviceConnectController` / `MovieSubDeviceController` | `{g, f}` | sub-device connect |
| `06` | `DeviceResetController` | — | **device reset** |
| `07` | `SubDeviceClearController` | `{0xFF}` | **clear sub-devices** (`f` defaults to `-1`) |
| `08` | `MusicSubDeviceEffectController` | bytes | per-sub-device music effect |
| `09` | `MovieSaturationController` | `{saturation}` | **saturation**, 0–100 |
| `0a` | `MovieGetColorController` | `{f, g}` | **colour sampling mode** (the All / Part choice) |
| `0b` | `MovieSoundController` | `{on, softness}` | **sound effects** and their softness |
| `0d` | `MovieDeleteController` | *empty* | **delete the DreamView** |

`0c` has no controller, and a live read returned `01 34 3b 01 01 01 37` — every field of which
appears elsewhere (`01` from sub `01`, `34` the first brightness, `3b` the `09` saturation,
`01 01` the `0a` pair, `01 37` the `0b` pair). It is a **read-only digest**, not a setting.

**Every captured frame reconciles with this table**, which is what promotes it from a class
listing to a reading:

```
33 60 01 01 01     -> on,  payload literally {1, 1}
33 60 01 00 01     -> off
33 60 07 ff        -> clear sub-devices; the controller's own default is -1
33 60 09 25/3b/2b  -> saturation 37, 59, 43
33 60 0b 00 35     -> sound off, softness 53
33 60 0b 01 4f     -> sound on,  softness 79      (same pair as the video sheet)
33 60 03 53 01     -> brightness 83 on member 1
33 60 0d 00        -> delete
```

Sub `03` was additionally **round-tripped**: writes at indices 0, 1 and 2 read back through
`aa 60 03` as `34 51 44`, in index order. A live three-member group answered with three bytes,
confirming the Sync Center counts as a member.

**Membership arrives separately**, as a `0xa3` multi-packet upload — see the Area Config below.

### 2.12a `0xa3` type `0x50` — DreamView membership + Area Config — **implemented**, 2026-08-27

One upload carries **both** who is in the group and how the video is sampled for each of their
zones. There is no separate Area Config command, and **no query returns membership** — this write
cannot be verified afterwards, and a previous group cannot be recovered from it.

```
a3 00  01 03 50 <count>  <entry…>
a3 01  …entries continue…
a3 ff  …tail…
```

Framed by the ordinary `0xa3` fragmenter (§5): `01` version, packet count, then type `0x50`, then
`Constant.makeSubDeviceBytes()` = `<count>` followed by one entry per device.

**Entry — every field named from `Area4Device.j()`, whose constructor labels each argument:**

| Bytes | Field | Notes |
|---|---|---|
| 1 | `isRgbic` | `mark == 1` |
| 1 | marker | `0` when a BLE address follows, `1` when a device NAME follows instead |
| 1 | `cmdVer` | a **cloud** field. Both devices in our only capture reported `0x0b` |
| 6 | BLE address | **REVERSED** — the app reads it in display order then appends last byte first |
| 1 | `areaNum` | zone count |
| N | `areaConfigs` | one region index per zone; **`0xFF` = that zone switched off** (`switchConfigs`) |

The reversal is proven on real data, not inferred: a captured entry reversed matches an address
recovered independently from another capture's handshake, while the unreversed form matches
nothing.

**A disabled zone is written as `0xFF`, never omitted** — the zone count and entry length stay
fixed however many zones are off.

**Per-model gates, for future devices.** These are the things that vary by hardware, and where
they live in our code:

| Gate | App source | Ours |
|---|---|---|
| Max sub-devices | `Constant.maxSubDeviceNumMovie` — 5, 7 or 10 by goodsType, **cloud lookup** | `ModelProfile.dreamview_max_sub_devices`, defaulting to the app's own ceiling of 10 |
| Who can host a group | the sync-centre device | `ModelProfile.supports_dreamview` |
| RGB vs RGBIC entry | `j()` branches on `areaNum > 1` | no divergence: at one zone both branches emit count-then-one-index, which is what our encoder already produces |
| `cmdVer` | cloud per device | a per-member parameter, defaulting to the observed `0x0b` |
| `areaNum` | cloud per device | the sub-device's own reported segment count |

**V1 vs V2 is a clean negative.** `movieFeastVersion()` selects
`MultiSetSubDeviceController4MovieFeast` or `…V2`, but the two are **byte-identical on the wire** —
same command type `0x50`, same `p()`, same opaque payload. They differ only in which app-internal
event they fire. No wire gate, so none is implemented.

**Removal is `33 60 0d`** (§2.12), reproduced byte-for-byte from the capture. It is implemented
*because* creation is not read-backable: without it the integration could reach a state it cannot
leave except through the vendor app. Reset (`0x06`) and clear-sub-devices (`0x07`) remain
unimplemented — neither undoes anything we can do.

### 2.12b Reading a DreamView group back — **live-verified 2026-08-27**

Two reads, and one thing they cannot tell you.

| Read | Answers |
|---|---|
| `aa 60 05` | one byte per sub-device **slot** (10 of them), its connection state. `0` = empty |
| `aa 60 0c` | a **digest** of the group's settings, in one frame |
| `aa 60 03` | the per-device brightness **list** — its length tracks membership |
| `aa 60 04` | same-brightness (All/Part) — has its own read, and is NOT in the digest |

**Digest layout**, byte-for-byte after `aa 60 0c`:

```
<on> <brightness> <saturation> <sound_effects> <colour_mode> <??> <softness>
```

Verified live by writing each field and reading it back: saturation → 37, sound effects on with
softness 70, member-0 brightness → 40, and the digest returned
`on=0 bright=40 sat=37 sfx=1 colour_mode=1 [5]=1 soft=70`. Byte `[5]` is `0x01` in every
observation and is **not** same-brightness — same-brightness was written OFF and read back `00`
from `aa 60 04` while `[5]` stayed `01`. It is left unnamed rather than guessed.

**You cannot enumerate the members.** The sync centre reports a state per slot and never the
addresses behind them; the vendor app knows who is in a group because its **cloud account** told
it, and indexes these bytes against that list. So a group created in the app is *detectable* —
count and connection state and settings — and its members stay anonymous.

**Live proof that it detects an app-made group**: before any write, a device we had never sent a
group to answered `aa 60 05` with two occupied slots — the group the owner had built in the app.
After `33 60 0d`, the same read returned all zeros, and `aa 60 03` shrank from three brightness
entries to one.

### 2.9a `0xa9` sub `0x10` — AI Filter — **implemented (toggle only)**, 2026-08-27

```
33 a9 10 0f <on> <8 filter bytes> <year u16 LE> <month> <day> <hour> <minute>   (timestamp UTC)
aa a9 10  -> the same shape
```

**BLE, not cloud** — the owner assumed this needed WiFi; both the read and the app's writes are on
the wire. Captured on 2026-08-26 turning it on and then off, the two frames differing only in the
enable byte.

**The eight bytes between the enable and the timestamp are the SELECTED FILTER**, built by
`AiFilterController` from an `AiFilterStatusBean` as four single bytes then two u16s, four of
which default to 50. They are zero in the capture only because no filter was configured.

**What cannot be done, and why.** The catalogue of filters is a CLOUD API:

```
GET  /bff-app/v1/filter/init       preset filters, per sku + device + ble/wifi firmware versions
POST /bff-app/v1/filter/recommend
POST /bff-app/v1/filter/apply
```

So filter *names and definitions never reach the device*. A BLE client can therefore only
**toggle the feature on and off, reusing whichever filter was last selected in the vendor app** —
it cannot list filters, name the current one, or choose a different one. The integration exposes
exactly that, says so in the entity docstring, and renders the eight bytes as a diagnostic so one
loaded filter can be told from another.

**A writer must preserve those eight bytes.** Zeroing them clears a selection that cannot be
rebuilt without the cloud; the implementation reads the register first and refuses outright if it
has not.

### 2.9b Music effects — the registry, and what an H66A0 actually accepts

`IMusicEffectStatic` names every effect id in pinyin and `strings.xml` carries the English, so the
names are lookup-able rather than guesswork. Sixteen ids exist for this family: the classic
`0x03-0x06` and the newer `0x30-0x3b`.

**The H66A0 accepts eleven of them, and silently refuses five.** Tested directly on 2026-08-27 by
writing `33 05 13 <id> 3c` and reading `aa 05` back:

| accepted | refused |
|---|---|
| `03` Rhythm, `04` Spectrum, `05` Energetic, `06` Rolling | `36` Waves (hailang) |
| `30` Bloom, `31` Shiny, `32` Separation, `33` Hopping | `38` Rhythm RGBIC |
| `34` Piano Keys, `35` Fountain, `37` Day and Night | `39` Energic RGBIC, `3a` Rippling, `3b` Swiping |

A refusal looks like success: the device **acks the write and keeps its previous mode**. All
eleven accepted ids read back correctly under the same method, so the negative is the method
working rather than failing.

**Rhythm and Energic exist twice** (`0x03`/`0x38`, `0x05`/`0x39`) — the app shows one entry and
picks by hardware. This H66A0 takes the classic ids despite being RGBIC, so whatever selects the
variants is not "is it RGBIC" alone, and no profile claims them.

### 2.13 The app's own opcode registry — **from APK**, 2026-08-27

Every command the vendor app can send is a class implementing `IController`, and the opcode is
the byte its `getCommandType()` returns. That method name survives obfuscation, which makes the
whole command set enumerable rather than guessable. Resolving inheritance across all decompiled
dexes yields **570 controller classes covering 93 distinct opcodes**.

Regenerate it with `tools/apk_opcode_registry.py` (see that script for the method). The short
version: parse each `.java` for its class, superclass and literal `getCommandType()` return,
then resolve each class's opcode through its ancestors.

**Read this table with one caveat, which is the whole reason `pacts.py` exists: an opcode is
scoped to a device family, not global.** `0x09` is `SyncTimeController` on one family and
`MovieSaturationController` on another. The same byte to a different device means a different
thing. Never implement a row here without establishing which pact the target device speaks
(§3.5a, and `pacts.py`).

Legend: ✅ implemented here · 👀 seen on our devices' wire but not implemented · blank: neither.

| Opcode | Classes | Representative controllers | |
|---|---|---|---|
| `0x00` | 14 | `Comm`, `Controller4Heart`, `OtaCommonController` … |  |
| `0x01` | 33 | `Controller4Gid`, `Controller4Uuid`, `HeartController` … | ✅ |
| `0x02` | 11 | `MultipleDiyController`, `MusicModeControllerV2`, `ControllerHeartPrepare` … |  |
| `0x03` | 9 | `ControllerStopSend`, `Controller4WifiFunc`, `Controller4DetailInfo` … |  |
| `0x04` | 11 | `ControllerInfo`, `DiyMultipleControl`, `Controller4H5107Info` … | ✅ |
| `0x05` | 15 | `MicController`, `ModeController`, `MicControllerV4` … | ✅ |
| `0x06` | 4 | `DeviceResetController`, `Controller4BindSubDeviceSuc`, `Controller4ReadBluetoothName` … | 👀 |
| `0x07` | 17 | `SnControllerV1`, `WifiInfoController`, `BasicInfoController` … | 👀 |
| `0x08` | 18 | `Controller4GwOp`, `LeakGwOpController`, `Controller4SetVolume` … |  |
| `0x09` | 5 | `ControllerSyncTime`, `SyncTimeController`, `MovieSaturationController` … | 👀 |
| `0x0a` | 5 | `AutoTimeController`, `MovieGetColorController`, `MultiNewScenesControllerV5` … |  |
| `0x0b` | 6 | `MovieSoundController`, `DelayCloseController`, `Controller4HardVersion` … |  |
| `0x0c` | 3 | `Controller4SoftVersion`, `MultiNewScenesControllerV6`, `MultiNewScenesControllerV7` |  |
| `0x0d` | 3 | `RedBlueController`, `MovieDeleteController`, `Controller4WifiHardVersion` |  |
| `0x0e` | 3 | `LimitController`, `ControllerLimit`, `Controller4WifiSoftVersion` |  |
| `0x0f` | 6 | `BulbNumController`, `ControllerSegment`, `LightNumController` … |  |
| `0x10` | 2 | `OpenController`, `Controller4SyncTime` |  |
| `0x11` | 9 | `SleepController`, `SleepControllerV2`, `SleepControllerV1` … | 👀 |
| `0x12` | 8 | `WakeUpController`, `WakeUpControllerV1`, `WakeUpControllerV2` … | 👀 |
| `0x13` | 3 | `DirectionController`, `NewTimerControllerV2`, `Controller4H5089TimerInfo` |  |
| `0x14` | 4 | `GradualController`, `ControllerGradual`, `Gradual4BleController` … | 👀 |
| `0x15` | 4 | `IPController`, `Controller4BuzzerGear`, `TimerDeleteController` … |  |
| `0x16` | 6 | `LightController`, `EnergySavingController`, `LightIndicatorController` … |  |
| `0x17` | 2 | `WifiLinkStarController`, `WifiLinkStarControllerV1` |  |
| `0x1a` | 1 | `AutoModeController` |  |
| `0x1f` | 1 | `Controller4ChildLock` |  |
| `0x21` | 2 | `ControllerSyncTriggers`, `Controller4LightSwitch` | 👀 |
| `0x22` | 1 | `Controller4LoraSpecification` |  |
| `0x23` | 2 | `NewTimerController`, `NewTimerV1Controller` | 👀 |
| `0x24` | 2 | `SetLightStartController`, `H682xDeviceUnbindController` |  |
| `0x27` | 2 | `WashRemindController`, `PreViewEffectV3Controller` |  |
| `0x28` | 2 | `Controller4NlSleep`, `DeletePreSetSceneController` |  |
| `0x29` | 1 | `SortPreSetSceneController` |  |
| `0x30` | 6 | `SubSwitchController`, `MultiDeviceController`, `ReportChartController` … | 👀 |
| `0x31` | 2 | `CameraPosController`, `Controller4PlayVoice` |  |
| `0x32` | 3 | `Controller4PauseVoice`, `CheckCameraController`, `CheckCameraInstallController` | 👀 |
| `0x33` | 4 | `VolumeController`, `TvHeartController`, `ControllerSwitchLR` … |  |
| `0x34` | 2 | `SwapLightController`, `GetDetailInfoController` |  |
| `0x35` | 3 | `StartTimeController`, `StartTimeControllerV1`, `WithoutInterruptController` |  |
| `0x36` | 5 | `LightOnOffController`, `ComposeLightController`, `WorryFreeAtNightController` … |  |
| `0x37` | 2 | `PromptToneController`, `UsbCheckStateController` |  |
| `0x38` | 3 | `UsbCheckController`, `InitLightController`, `GuideLightController` |  |
| `0x39` | 2 | `ControllerDirection`, `CheckDirectionFinishController` |  |
| `0x40` | 16 | `ControllerIcNum`, `IcNumController`, `ReadIcController` … | ✅ |
| `0x41` | 5 | `MultiMusicController`, `DeviceInfoController`, `Controller4OnOffMemory` … |  |
| `0x42` | 5 | `SPPMacController`, `CancelBTController`, `ControllerRefreshIc` … |  |
| `0x43` | 6 | `CheckIcController`, `ControllerCheckIc`, `Compose4LightCali` … |  |
| `0x44` | 4 | `ControllerCutCali`, `CutCaliController`, `InstallCaliController` … |  |
| `0x45` | 1 | `ControllerMontageBrightness` |  |
| `0x46` | 1 | `ControllerResetDeviceNet` |  |
| `0x48` | 1 | `ControllerPartScenesInfo` |  |
| `0x49` | 3 | `WifiMacControllerV2`, `WifiSoftVersionControllerV2`, `WifiHardVersionControllerV2` |  |
| `0x4a` | 1 | `Controller4CheckNetwork` |  |
| `0x50` | 2 | `MultiSetSubDeviceController4MovieFeast`, `MultiSetSubDeviceController4MovieFeastV2` |  |
| `0x51` | 1 | `ColorSetMultiController` |  |
| `0x52` | 1 | `SetColorMultiController` |  |
| `0x54` | 1 | `MovieOpenController` |  |
| `0x55` | 1 | `SubDeviceProtocolMultiController` |  |
| `0x56` | 1 | `MultiNewScenesControllerV8` |  |
| `0x57` | 1 | `MultiDiyGraffitiControllerV3` |  |
| `0x58` | 6 | `SetAiActionController`, `MultipleDiyControllerV3`, `FeastSceneMultiController` … |  |
| `0x5a` | 1 | `MultiNewScenesControllerH60B0` |  |
| `0x61` | 1 | `MusicBrightnessController` |  |
| `0x70` | 1 | `ControllerSyncTriggers4H5901` |  |
| `0x71` | 2 | `ControllerOnlineMusicPlayerState`, `OnlineMusicPlayerStateController` |  |
| `0x72` | 1 | `PreSetInfoController` |  |
| `0x73` | 1 | `PreSetColorController` |  |
| `0x74` | 1 | `PreSetSceneController` |  |
| `0x75` | 1 | `SetPlayerStateController` |  |
| `0x76` | 3 | `PreViewEffectController`, `PreViewWakeUpController`, `PreViewEffectV2Controller` |  |
| `0x79` | 3 | `ControllerOnlineVolume`, `OnlineMusicVolumeController`, `OnlineMusicReadVolumeController` |  |
| `0x7a` | 1 | `WhiteNoiseSwitchController` |  |
| `0x7b` | 1 | `PresetMixInfoReadController` |  |
| `0x7c` | 1 | `PresetMixDeleteController` |  |
| `0x83` | 2 | `MicSetRgbController`, `EditDisplayRemindController` |  |
| `0x84` | 1 | `EditAlarmClockController` |  |
| `0x85` | 1 | `CloseAlarmClockController` |  |
| `0x90` | 1 | `MicColorCmdController` |  |
| `0xa2` | 3 | `ReadBulbColorController`, `ReadLightColorController`, `BulbStringColorController` |  |
| `0xa3` | 4 | `Gradual4BleWifiController`, `ControllerGradual4BleWifi`, `Gradual4BleWifiControllerV1` … | ✅ |
| `0xa4` | 2 | `Controller4RemotePair`, `MultiNewScenesControllerV9` |  |
| `0xa5` | 4 | `LocalColorReadControllerV1`, `BulbStringColorControllerV3`, `BulbStringColorControllerV2` … | ✅ |
| `0xa6` | 2 | `LogoController`, `OnOffAutoInductionController` |  |
| `0xa7` | 2 | `SensitiveController`, `CaliLightBeltController` |  |
| `0xa9` | 13 | `Controller4Hdmi`, `HDRCaliController`, `AiActionController` … | ✅ |
| `0xaa` | 2 | `CheckLightController`, `CheckLightInstallController` |  |
| `0xab` | 2 | `DynamicApiSupportController`, `DynamicApiSupportControllerV1` | ✅ |
| `0xae` | 1 | `RelativeBrightnessController` | ✅ |
| `0xb7` | 1 | `Controller4AudioFrom` |  |
| `0xb8` | 1 | `StopPreViewAiActionController` |  |
| `0xba` | 2 | `ControllerEyeshadow`, `ControllerLowBlueLight` |  |
| `0xee` | 1 | `OtaPrepareController` |  |
| `0xef` | 1 | `ControllerProtocol` | ✅ |

Most rows are appliances — kettles, humidifiers, cameras, water sensors — and will never be in
scope for an LED integration. The rows worth attention are the ones marked 👀: opcodes our own
devices actually emit that we do not yet handle.

Three finds from this table are already folded into this document: `0xae` is
`RelativeBrightnessController` (§2.6.3, and it turned out our existing H6199 builder reproduces
the H66A0's frames byte-for-byte), `0xb7` is `Controller4AudioFrom` — which is the music
input-source control previously recorded here only as a hypothesis — and the `Movie*Controller`
family (`0x09` saturation, `0x0a` get-colour, `0x0b` sound, `0x0d` delete) independently
confirms the DreamView sub-command numbers in §2.12, which had been derived from captures alone.

### 2.6.4 A second device, and a second encryption generation — **verified 2026-08-25**

Everything in §2.6 had been read from one family. An **H61F5** — encryption **v1**, pactType
3, no `2b12` characteristic at all — was captured being driven by the vendor app, and the
capture decrypted in full (149/153 frames to a valid checksum; the other four are the
handshake). Its answers are the first independent check of the query table.

Six queries that had been read on one device answer here with **the documented field layout
intact**:

| Query | H61F5 reply | Fits the documented layout |
|---|---|---|
| `aa 11` sleep timer | `00 1e 0f 0f 00 ff 32` | enable 0, startBri 30, closeTime 15, curTime 15, defaultLight 0, RGB (255,50,0) |
| `aa 12` wake-up alarm | `ff 64 00 00 80 0a 00 ff ae 54` | enable 0xFF, endBri 100, wakeHour 0, wakeMin 0, repeat 0x80, wakeTime 10, defaultLight 0, RGB (255,174,84) |
| `aa 14` wifi MAC | six bytes | see below |
| `aa 20` wifi hardware version | `"1.04.02"` | ASCII |
| `aa 21` wifi software version | `"1.03.08"` | ASCII |
| `aa 23 ff` timers | `ff` + 4 × `00 00 00 80` | index 0xFF, then four `{enable/type, hour, minute, repeat}` |

**Confirmed again on an H1A42 (v2) the same day.** All six answer there too, and `aa 11`,
`aa 12` and `aa 23` return **byte-identical** payloads on both devices — which is what an
unset factory default looks like, and is worth knowing before anyone reads meaning into the
values. `aa 20`/`aa 21` differ per device, as versions should, and `aa 14` returns a
different MAC on each. So the six are established across **two devices in two encryption
generations**, which is as far as this can be taken without more hardware.

The **write** forms are captured too — on the H66A0, in `capture2.pklg`, which had been sitting
in this project the whole time. Seven frames, and the body is **the same layout in both
directions**:

```
33 11 01 1e 0f 0f 00 00 00 00    sleep on:  startBri 30, closeTime 15, curTime 15
33 11 01 3a 0f 0f 01 ff 00 6e    sleep on:  startBri 58, defaultLight 1, RGB (255,0,110)
33 11 00 3a 0f 0f 01 ff 00 6e    sleep off: same parameters, enable byte cleared
33 23 00 81 03 02 83             timer slot 0: enabled, 03:02, repeat 0x83
33 23 00 01 03 02 83             timer slot 0: same, enable bit cleared
```

`33 23` writes **one slot per frame** (`<index> <enable/type> <hour> <minute> <repeat>`), where
the read returns all four at once. `0x12` (wake-up alarm) has a read form but no captured write.

> Recorded because the mistake is instructive: this was written up as "readable, not settable"
> on the strength of two new captures, without checking the *existing* one — which not only
> contained the writes but had them **already labelled** by `decode_commands.py`. Absence of
> evidence in the newest artifact is not absence of evidence.

**`0x14` really is the WiFi interface.** The name was previously an inference from the app's
own field naming. The MAC this device returned over BLE was then found as a **live host on
the local network**, which no BLE address ever is. That is what promotes it from "a second
MAC that is not the BLE address" to an identification.

It stays excluded from every artifact as PII. Which interface it belongs to does not change
that — a hardware address identifies a specific unit either way — and the exclusion now
covers a value that demonstrably locates the device on its owner's network.

### 2.6.5 Reading a failure: uniform silence versus partial function

A triage rule, learned the expensive way. Two failure shapes look similar in a bug report and
have nothing to do with each other:

* **Uniform** — the device connects, acknowledges every write at the ATT layer, and *nothing
  ever works*. No query is answered, no command takes effect. That is a **transport or
  encryption** fault: the frames are not being understood at all. An encryption-v1 device
  driven in plaintext produces exactly this, and it produced it for five sessions here.
* **Partial** — power works but colour does not; on works but off does not; brightness moves
  erratically. The transport is **fine**; the opcode, the dialect or the model profile is
  wrong.

They are worth separating before any investigation starts, because the second shape can never
be an encryption problem and the first is almost always one. A survey of 192 open issues
across two integrations on 2026-08-25 found the partial shape repeatedly and the uniform shape
not once — which is why encryption v1 is offered here as a prerequisite for devices not yet
supported, and **not** as an explanation of anybody's existing bug report.

### 2.10 `0xAB` — a paged read channel — **verified 2026-08-25**, not implemented

Named in the app as `BleProtocolConstants.MULTI_READ_AB = -85`, and reached by
`AbsController4WifiSingleSendMultiBack` (via `Controller4ReadWifiFuncList`) and by
`DynamicApiSupportController`. Both captures use it; neither integration implements it.

Unlike every other frame here it is **multi-frame with reassembly**: one request, an
indeterminate number of replies, terminated by a sentinel.

```
HOST>  ab 01 <field>                                    request one field
<DEV   ab 00 <pages> <len hi> <len lo> 01 <field> …     header, then the first chunk
<DEV   ab 01 …  ab 02 …  ab 03 …                        continuation, sequentially numbered
<DEV   ab ff …                                          final chunk
```

Payloads are ASCII. Reassembled from an H61F5:

| Field | Reassembled value | Reading |
|---|---|---|
| `02` | `01` | a flag — one byte, no continuation |
| `05` | a 16-character hex string | an identifier |
| `04` | a 10-digit value followed by ~130 hex characters | the leading digits are a Unix timestamp, and it matched the capture's own date |

A second device confirms the shape and sharpens the reading. An **H66A0** answers fields
`01`–`06`, and what they carry is **provisioning identity**:

| Field | Content |
|---|---|
| `01` | a **Matter onboarding payload** (`MT:` prefix, 21 characters) |
| `02` | a one-byte flag |
| `03` | a one-byte value |
| `04` | a Unix timestamp followed by ~130 hex characters — a token |
| `05` | a 16-character hex identifier |
| `06` | an 11-digit numeric identifier |

> **Treat `0xAB` output as credential material.** Field `01` is a Matter setup code: it is the
> pairing secret for commissioning the device onto another fabric, and field `04` is a token.
> No value from this channel appears anywhere in this repository, and none should. It is
> named here by *shape* only, for the same reason BLE addresses are.

So `0xAB` is a **capability and identity read**: "dynamic API support" plus a WiFi function
list. That makes it the only device-side capability route found so far besides
`pactType`/`pactCode` and the hardware version — and unlike those it is **structured and
extensible** rather than a pair of integers.

It is documented here and deliberately **left unimplemented**. It is a whole read channel
with reassembly semantics, on a WiFi-oriented surface, and the payload fields are identified
by shape rather than by name. Adding it belongs in its own change, on its own evidence.

## 3. Capability discovery

**What can a client determine at runtime, without a model table?**
More than we expected. This section is the practical answer.

> **Live probe, 2026-08-23.** A read-only sweep against the H66A0 over an encrypted
> session answered most of the open queries in this section; the results are folded
> into the tables below and marked **verified** where bytes were seen. The device
> under test has **no camera module attached**, so `aa 32` and the whole `aa a9`
> surface stayed silent — those remain unverified. Raw replies are quoted inline.


### 3.1 Encryption version — the `2b12` characteristic

**verified** for format 1; **from APK** for format 2.

A GATT read of `00010203-0405-0607-0809-0a0b0c0d2b12` returns a small blob whose
first byte is a **format tag** (`BgcInfoReader.d()`):

```
format 1:  01 <encryptVersion> ...
format 2:  02 <encryptVersion> <flag> <pactType hi> <pactType lo> <pactCode> ...
```

Our H66A0 returns `01 02 00 …` → format 1, encryption version 2 → the AES-GCM
path in `PROTOCOL.md`. Version 0 or a missing characteristic means plaintext.

Format 2 is the interesting one: it carries **pactType and pactCode**, the two
values that drive nearly every per-model behaviour decision in the app
(`BaseBgcInfo.Companion.a()`, consumed by `CommEventGattCallback.d()` and
`ThGattCallbackImp.d()`). The `flag` at `[2]` selects a value of 3 vs 2 in the
app's device cache; **we do not know what it means.**

### 3.2 Brightness scale — solvable at runtime

**from APK**, with the H66A0 half **verified**.

The app does not use a brightness lookup table keyed on SKU. It computes:

```java
getBrightnessRange(...) = isBK ? {0, 1, 100}       // send 1..100 directly, clamped
                                : {1, 20, 254}      // scale a 0..100 percentage into 20..254
                                  or {1, 6, 254}    // ditto, older devices
```

`range[0]` is a mode flag: `1` = scale, `0` = clamp. Scaling is
`NumUtil.calculateProgress(max, min, pct) = min + (pct - 1) * (max - min + 3) / 100`.

And `isBK` is a function of `pactType` / `pactCode` — which the device supplies:

```java
// homelightv1
isBk(goodsType, pactType, pactCode) = goodsType == 16 && pactType >= 2 && pactCode >= 1
// dreamcolorlightv2
e(goodsType, pactType, pactCode)    = goodsType in {123,136,141,175,176,178,187,193}
                                      || (goodsType == 21 && pactType >= 2 && pactCode >= 1)
```

`goodsType` comes from the cloud, so the app's exact expression is not
reproducible offline. But `pactType`/`pactCode` are readable three ways
(§3.4), and a client that wants to avoid a SKU table has a better option
anyway:

**Read `aa 04` and look at the answer.** A device on the 0–254 scale reports a
value above 100 at anything over ~35 % brightness. A device on the 0–100 scale
never reports above 100. That is not a complete discriminator on its own — a
0–254 device sitting at low brightness also reports ≤ 100 — but combined with
"assume 0–100 until you see a value > 100" it degrades safely: the failure mode
is a device that is dimmer than requested until the first reading above 100,
never a device that ignores the command.

**verified for H66A0**: `aa04` returned `0x64` = 100 with the light at full,
and `3304 25` = 37 was accepted — a 0–100 device.

> `Beshelmek/govee_ble_lights` currently passes Home Assistant's 0–255
> brightness straight through, which is wrong for 0–100 devices like the H66A0.

### 3.3 Segment count — solvable at runtime

**from APK** for the direct read; **verified** for the indirect one.

* `aa 40` returns **two** values, not one. Re-confirmed 2026-08-24 through a Home
  Assistant integration that probes it once per connection and sizes its
  per-segment services from `[2]`; the frames were
  `aa 40 00 00 … ea` out and `aa 40 00 5a 0e 00 … be` back. On the H66A0 it answered `00 5a 0e`:
  `[0:2]` = 0x005A = **90** big-endian, and `[2]` = 0x0E = **14**. The first is the
  IC count the `IcNumController` name suggests; the second is the segment count, and
  14 is independently confirmed twice over — by paging `aa a5` (4+4+4+2) and by the
  `0x3FFF` mask the app itself writes. **verified**, but on one device, so read `[2]`
  as "a segment count on this model" rather than as a settled field for the family.
  Note this is consistent with, rather than a correction to,
  `teh-hippo/ha-govee-led-ble`'s finding that the H6199's `aa 40` answer of 38 is
  *not* its app segment count: 38 would be that device's `[0:2]`, a different field.
* `aa a5 <page>` can be paged until a page comes back with fewer than 4 non-zero
  entries. Our H66A0 gave 4+4+4+2 = **14**, matching the `0x3FFF` mask the app
  used. **verified**

Either beats the hardcoded `SEGMENTED_MODELS` list that
`Beshelmek/govee_ble_lights` uses today.

### 3.4 Colour dialect — *not* fully solvable at runtime

This is the honest gap. We found **no** query that reports which colour dialect
a device speaks. What is available:

* `aa 05` reports the **current** sub-mode. If the device is already in a colour
  mode, the sub-mode byte in the reply tells you the dialect directly
  (`0x15` on our H66A0, in the capture). If it is in a scene or music mode, it does
  not.

  **Both halves of that were seen on one device on 2026-08-23, which is what makes
  the recommendation testable rather than theoretical.** Probed cold, before anything
  had been written, the H66A0 answered sub-mode **`0x00`** — not `0x15`, not any of
  the four documented `color_mode` values, and not a value we can name. After a
  `33 05 15 01` colour write it answered **`0x15`**, the dialect it had just been
  addressed in. So the probe is reliable *once the device is in a colour mode* and
  silent otherwise, exactly as described — but "otherwise" includes at least one
  unnamed resting mode, and on a TV backlight that is the state you are most likely
  to find it in at connect time. **Treat `aa 05` as a confirmation, never as the only
  source, and keep the fallback.** What `0x00` means is an open question; it is not
  reinterpreted here to fit.
* `pactType` / `pactCode` correlate with dialect in the app's own logic, but
  the mapping runs through `goodsType`, which is cloud-only.

Practical recommendation: read `aa 05` at connect time; if the reply's sub-mode
is a colour sub-mode, use that dialect. Otherwise fall back to `0x15` for
devices reporting encryption version 2 (all of which are recent enough to use
it, as far as we have seen — **inferred**, from a single device, so treat it as
a default rather than a fact), and to `0x02` otherwise.

### 3.5 pactType / pactCode — three routes

**from APK.** These are the app's own capability keys and they are available
without the cloud:

1. **The BLE advertisement.** Govee's manufacturer-specific AD element
   (`BleUtil.parseBleBroadcastPact`) is laid out:

   ```
   [len] [0xFF] [flags] [0x88] [0xEC] [pactType hi] [pactType lo] [pactCode] ...
                  │       └──── company id 0xEC88, matched literally
                  ├─ bit 6 (0x40): device supports encryption
                  └─ bits 0-3    : broadcast protocol version
   ```

   So **encryption support, pactType and pactCode are all in the advertisement**
   — no connection required. **verified 2026-08-23**, against a real scan record and
   cross-checked against the same device's answer to `aa EF`.

   An H66A0 broadcasts manufacturer-specific data that a BLE stack reports as
   company id `0x8843`, payload `ec 00 02 01 01`. Company id is parsed little-endian
   from the first two bytes, so on air those bytes are:

   ```
   43     88 ec     00 02   01    01
   │      └──┬──┘   └─┬─┘   │     └── trailing byte, unidentified
   │         │        │     └──────── pactCode = 1
   │         │        └────────────── pactType = 2 (big-endian)
   │         └─────────────────────── Govee's literal 0x88 0xEC magic
   └───────────────────────────────── flags = 0x43
   ```

   `0x8843` is **not** a Bluetooth SIG company identifier. Govee's flags byte simply
   occupies the low half of the field, which is why a generic
   "encryption-capable Govee" matcher cannot be written as a single company id: the
   value moves with the flags. Decoding flags `0x43`: bit 6 (`0x40`) set = **device
   supports encryption**, bits 0-3 = `3` = broadcast protocol version 3.

   The claim checks out end to end. The advertised pactType/pactCode (2, 1) are
   byte-identical to what the same device answers to `aa EF` over the connection, and
   the encryption bit is correct: this device does require the AES-GCM path, which its
   `2b12` marker independently confirms. Two routes agreeing on the same pair is what
   promotes this from a parser reading to an identification.

   Only the one flags value has been observed. Reading bit 6 out of *other* flags
   bytes is a mechanical consequence of the parser, not something seen on hardware.

2. **The `2b12` read**, when it returns format 2 (§3.1).

3. **`aa EF`** over the connection (`PactController`) → `pactType` big-endian in
   `[0:2]`, `pactCode` in `[2]`. **verified 2026-08-23**: the H66A0 answered
   `00 02 01`, agreeing with its own advertisement.

### 3.5a How the app decides what a device supports — the complete picture

**from APK, 2026-08-24.** Asked directly: are there capability gates we missed?
There are three mechanisms, and only one of them is reachable from a BLE client.
This is the map, because knowing which is which decides whether a local client can
ever reproduce the app's behaviour.

**1. `Support.isXxx(goodsType)` / `Support.supportXxx(goodsType, versions…)` — per-pact SKU tables.**

Each product family has its own `Support` class with hardcoded tables. For
`com.govee.pact_h605b.pact.Support`:

| Gate | Condition |
|---|---|
| `isHdmiSku` | goodsType ∈ {138, 142, 192, 243} = H6601–H6604 |
| `isCameraSku` | goodsType ∈ {120, 82, 360} = H605C, H605B/D, H2A40 |
| `supportHdmi` | same as `isHdmiSku` |
| `supportBorderRemove` | H2A40, or H6604, or H6601/H6602 with sw ≥ 1.00.38 and hw = 2.01.01, or H6603 with sw ≥ 1.00.04 and hw = 2.01.11 |
| `supportHDR` | H6603/H6604 with sw ≥ 2.02.11 and hw = 2.01.11 |
| `supportColorCalibration` | H6602/H6603/H6604, or H6601 with sw ≥ 1.00.16 |
| `supportOffMemory` | H6608, H6603, H6604, H2A40 |
| `supportSegmentRelativeBrightness` | H6603/H6604/H2A40 unconditionally, others by exact hw/sw version |
| `supportAiOta` | H6601–H6604 |
| `supportPaoMianCali` | H605C, H2A40 |

Note the shape: **`goodsType` is a cloud field, but the version comparisons use the
firmware and hardware strings a client already reads over BLE** (`aa 06`, `aa 07`).
So the version half of every gate is reproducible; only the family half is not.

Which pact serves a device is also `goodsType`-keyed, via `SubLib.keys()`:

| Pact package | goodsTypes |
|---|---|
| `pact_h605b` | 82, 120, 138, 142, 172, 192, 243, 360 |
| `pact_tvlightv3` | 23 |
| `pact_tvlightv2` | 24 |
| `pact_tvlightv4` | 25 |

**The string `"H66A0"` appears nowhere in any pact package** — it occurs three times
in the whole APK, all in shared colour-temperature and white-balance lists, where it
is grouped with H2A40, H6098, H6099, H605A, H66A1, R2A80. So our device is routed
purely by a cloud `goodsType`, and the `pact_h605b` tables above are **its siblings'
rules, not necessarily its own**.

**2. `Config4DeiceFuc` — a server-supplied per-device function list.**

`com.govee.base2light.pact.newdetail.config.Config4DeiceFuc` extends `AbsConfig`,
is cached per `sku_device`, and carries `getFucs()`, `getModes()`, `getAiConfig()`
and a list of `Support4Fuc`. The function-type IDs are UI features:

```
1 ai · 3 aiRobot · 4 effectLib · 7 autoPlay · 8 material_lib · 10 room_feast
11 colourway · 12 random_color · 13 life_detail · 14 delay_close · 15 ai_filter
```

`AbsVideoNewDetailVm.supportAiFilter()` consults exactly this. **Pure cloud — no BLE
route at all.**

**3. `pactType` / `pactCode` — the only one a BLE client can read** (§3.5).

**And the negative result that matters: there is no device-reported capability
bitmap.** `BleProtocolConstants` names ~228 constants and not one of them is a
support/feature/capability query. A local client cannot ask a Govee device what it
can do. The practical answer is the one this document has been arriving at
throughout: **ask the register and see whether it answers.** That is what
`teh-hippo/ha-govee-led-ble` does — the probe runs once per connection, and an
entity backed by a register that stayed silent goes unavailable. It beats
reproducing tables keyed on a value the cloud owns.

### 3.5b OTA / chip family — readable from the hardware version — **from APK**, 2026-08-24

A fourth device-side signal, and the only one besides `pactType`/`pactCode` that a
local client can compute. `OtaType.parseHardVersion(hw)` derives the silicon family
**from the hardware-version string alone** — no cloud field, no `goodsType`:

```java
// com.govee.base2home.ota.OtaType.parseHardVersion(String)
//   requires length 7 and exactly three dot-separated fields
major "1"                        -> Telink
major "2" and minor "01"         -> BK_01
major "3" and minor "01|02|03|…" -> FRK_01 | FRK_02 | FRK_03 | …
```

So `aa 07` selector 3 answers this question too. Our H66A0 reports `3.07.01` and is
therefore **FRK_O7**; an H6199 reporting `3.02.01` or `3.02.10` is **FRK_02**, which
`isFRKOtaV1()` accepts.

This matters because `isTelinkOta()` / `isFRKOtaV1()` appear inside capability gates
across every pact, and they were previously assumed to need something we could not
read. They do not. The clearest consequence is the H6199 scene/video gate
`supportVideoSoundAndServiceScenes`, which collapses from four unknowns to one
readable test:

> FRK hardware (which `3.02.xx` is) **and** software >= `1.07.02`.

That is fully evaluable by a BLE client. It is still not a reason to *refuse*
anything — see the firmware-floor argument in `INTEGRATION_NOTES_hippo.md` §2d —
but it is the difference between a gate we can explain and one we can only guess at.

### 3.6 What is *not* discoverable

Stated plainly, because a wrong "you can detect this" is worse than none:

* **Colour temperature range** (min/max Kelvin) — cloud only.
* **The scene catalogue** — cloud only; the model JSONs are a snapshot of it.
* **`goodsType`** — cloud only. Several of the app's own decisions depend on it,
  which is why the app's exact logic cannot be reproduced offline. Every
  decision that matters for basic control has a device-side alternative above.
* **Which music/mic effects a device supports** — no query found.

---

## 4. Device events (`0xEE`)

**verified** for `0xEE30` type 1 on H66A0; **from APK** for the other types.

```
ee 30 <detail type> <data...>
```

`0x30` is `NOTIFY_DETAIL`. The detail type at `payload[0]`:

| Type | Meaning |
|---|---|
| `1` | light status |
| `2` | energy saving |
| `3` | battery |
| `4` | music |
| `5` | volume |
| `6` | without-interrupt |
| `7` | sleep |

For type 1 the data is family-specific: `h705a` reads bit 1 of the next byte as
the on/off state, `pact_h605b` reads bits 4–7 as four separate light bars.

On the H66A0 the byte after the type **is** the power state, observed both ways:

```
33 01 00   →   ee 30 01 00 …      power off
33 01 01   →   ee 30 01 01 01 …   power on
```

`0xEE` is also `SINGLE_OTA_PREPARE` in the write direction — the same byte,
different direction, unrelated meaning.

These events are what make real state reporting possible instead of optimistic
updates: the device pushes them on any change, including changes made from a
remote, another phone, or the device's own buttons.

> Note for anyone reading the capture directly: the original hand-written frame
> labels in the brief were offset by a few frames. The decrypted bytes are the
> ground truth — the frame labelled "POWER ON" is `3301 00`, i.e. off.

---

## 5. Multi-packet writes

**verified** on the wire (capture 2 contains 57 of them), and cross-read
against `MultipleControllerCommV1.makeSendBytesV2` in the APK.

Payloads longer than a 20-byte frame — scene parameters, DIY definitions, music
palettes — are split across several 20-byte frames, each individually
checksummed:

```
first    [proType] [0x00] [0x01] [total packets] [header bytes...] [data...]
middle   [proType] [n]    [17 bytes of data...]                     n = 1, 2, 3, ...
last     [proType] [0xFF] [remaining data...]
```

`total packets` counts every frame including the first and the last. `proType`
is `0xA3` throughout for this device. Data resumes at offset 2 in every frame
after the first, so the first frame carries `15 - len(header)` bytes of data.
Trailing space in the last frame is zero-padded.

**Cross-checked against an independent implementation.** Rebuilding all 57
captured uploads with `Beshelmek/govee_ble_lights`'
`govee_utils.prepareMultiplePacketsData` — a reimplementation of
`makeSendBytesV2` written without reference to this capture — reproduces every
frame byte-for-byte: 49/49 scene parameter (`0x02`), 6/6 graffiti (`0x03`),
1/1 DIY (`0x04`), 1/1 music (`0x41`, the two-byte header). Payload sizes ranged
from 30 to 218 bytes, i.e. 2 to 13 packets.

> A comparison that trims the reassembled payload with `rstrip(b"\x00")`
> instead of the blob's own declared length reports 46/49 rather than 49/49.
> That is an artefact of the trim, not a disagreement: a scene blob's last
> effect ends in a zero-filled `tail4` (§5.2), so `rstrip` eats real payload and
> the rebuild comes out one packet short. Trim to the declared length.

There is a simpler variant, `makeSendBytesV0`, whose first frame is
`[proType] [0x00] [0x00] [total] [command]` with no data, and whose last frame
is empty. Both exist in the app; we have only seen the form above.

Pacing: `AbsMultipleControllerV1.r()` returns 300 ms (100 ms for scenes and
graffiti), and the app waits for each frame's write callback before sending the
next.

### 5.1 The header byte is `getCommandType()`

The header names what the payload *is*. It is the controller's
`getCommandType()`, and the device echoes it in the ACK:

```
a3 <type> <result>          result 0 = OK      (AbsMultipleControllerV1.j)
a3 41 <musicCode> <result>                     (AbsMultipleControllerV2.j)
```

| Type | Payload | Controller | Seen |
|---|---|---|---|
| `0x02` | scene effect parameter | `MultiNewScenesControllerV2` | 49× |
| `0x03` | DIY graffiti (per-LED painting) | `MultiDiyGraffitiController` | 6× |
| `0x04` | DIY effect | `MultipleDiyControllerV1` / `V2` | 1× |
| `0x41` | music effect palette + params | `MultipleController4Music` | 1× |

Other types exist in the APK for other families — `0x01`, `0x07`, `0x0A`,
`0x0C`, `0x40`, `0x50`, `0x56`, `0x58`, `0x5A`, `0x11` — read the matching
`Multi*Controller` class if you need one.

**`0x41` carries a two-byte header.** `MultipleController4Music` extends
`AbsMultipleControllerV2`, and `makeWriteMultipleBytes(AbsMultipleControllerV2)`
passes `{getCommandType(), p()}` — where `p()` is the music code. So its first
frame is `a3 00 01 <total> 41 <musicCode> <data...>`, and its ACK is
`a3 41 <musicCode> <result>`. Every other type here uses a one-byte header.

**Activation is a separate frame.** The upload only stages the data; the mode
frame that follows selects it:

| Upload | Followed by |
|---|---|
| `0x02` scene param | `33 05 04 <sceneId LE16> [variant]` |
| `0x03` graffiti | `33 05 0a <diyIndex> <?> 03` |
| `0x04` DIY | `33 05 0a <diyIndex> <?> 04` |
| `0x41` music | `33 05 13 <musicCode> <sensitivity> ...` |

> **This has now been executed against a device — 2026-08-24, verified.** Until
> then the "upload then activate" finding had only ever been *read* off a capture.
> Driving it from Home Assistant against an H66A0: seven `0xA3` frames followed by
> `33 05 04 c5 38` put scene 14533 (Forest) on the light, and the device confirmed
> it by answering `aa 05 04 c5 38`. The frames were byte-identical to the ones the
> Govee app itself sent for that scene, checksums included.
>
> Across a whole capture — 49 uploads with their activations, rebuilt from Govee's
> published per-SKU catalogue alone — **45/45 upload frames and 48/48 activation
> frames matched byte for byte, with zero differences.** So a client that has the
> `scenceParam` needs nothing else: no cloud call at activation time, no state
> from the app.
>
> The trailing `[variant]` byte is `0x00` for 48 of the 48 captured activations.
> Three further captured activations, for scene codes absent from the current
> catalogue (`14353`, `14359`, `14371`), carry `0x02` there. Still unnamed.

The last byte of the `33 05 0a` DIY frame is the same protocol code as the
upload header (`IDiyParse.getProtocolCode()` — `3` for `DIYGraffitiParser`,
`4` for `DiyProtocolParseShare0x00`). `Beshelmek/govee_ble_lights` sends the
upload but **not** the trailing activation, which is worth knowing if you are
debugging why a scene uploads but does not visibly apply.

### 5.2 Scene effect parameter (`0x02`)

**verified.** This is the base64 `scenceParam` from the cloud model JSON,
base64-decoded and forwarded **verbatim** — `ScenesOp.e()` does
`new MultiNewScenesControllerV2(sceneCode, Encode.decryByBase64(param))` and
never touches the bytes. So the app is not the authority on the layout; the
firmware is. But the app *validates* the blob before sending, and that
validator — `ScenesRgbIC.isValidProtocolBytes` / `f()` / `i()` — walks every
field, which is where the layout below comes from.

```
blob:  [effectCount]  ( [len] [effect body (len bytes)] ) * effectCount  [zero pad]
```

```
effect body:
  0        packed byte, two 4-bit fields          (ScenesRgbIC.h)
  1        style                                  (c(): ==3 forces protocol v1)
  2..3     two bytes
  4        brightness byte                        (d() "parseBrightnessByte")
             high nibble = algorithmType 0..2
             low  nibble = type 0..3
  5        N = number of 6-byte parameter blocks
  6        N x 6 bytes
  p = 6+6N
  p        colorIc byte                           (e() "parseColorIcFromByte")
             bit 7   = order
             low nib = colorType 0..3
  p+1      byte
  p+2      byte
  p+3      M = colour count
  p+4      M x 3 bytes RGB
  q = p+4+3M
  q..q+3   3 bytes
  q+3..q+7 4 bytes
```

so `len == 17 + 6N + 3M`.

**Checked hard.** This parser consumes, byte-exactly with only zero padding
left over, **all 521 blobs available**: the 49 uploaded in capture 2 *and* the
472 hardcoded base64 scene parameters in `ScenesRgbIC.java`. `scene_param.py`
reproduces it:

```
$ python3 scene_param.py
APK corpus (ScenesRgbIC)      472 parsed, 0 failed
capture2.pklg uploads          49 parsed, 0 failed

total 521 blobs, 0 failures
```

The names above are the app's own (`algorithmType`, `type`, `order`,
`colorType`). We have **not** identified what the 6-byte blocks, the `p+1`/`p+2`
bytes or the 7 trailing bytes mean — the app never interprets them, and we are
not going to invent names for them. Speed and direction are adjusted by the app
through the *cloud* `SpeedInfo` / `SceneDirection` config, by picking a
different `scenceParam`, not by patching bytes.

The one field the app does write into a scene blob is the brightness byte:
`parseBytes4BrightnessV1Change` rewrites body offset 4's **high nibble** to
`0001`, leaving the low nibble. That independently confirms offset 4 and the
nibble split.

There is a **V2 shape** for newer devices, `isValidProtocolBytes4RgbicV2`: the
effect count is at `[1]` instead of `[0]`, and each body carries an extra
`[flag][len][len bytes][byte]` tail after the 4 trailing bytes. The H66A0 uses
the V1 shape above. `ScenesOp.f()` strips two leading bytes for the graffiti
scene type, which is the same family of variation.

### 5.3 DIY graffiti (`0x03`)

**verified** — 6 uploads in capture 2, all parsing byte-exactly.

Per-LED painting: a background colour plus explicit lists of LED indices per
colour.

```
0        a          (varied 0x09, 0x0a, 0x02 across the capture; meaning unknown)
1        b          (varied 0x33, 0x24; meaning unknown)
2        brightness (0x64 = 100 in every upload we have)
3..5     background RGB
6        groupCount
per group:
  0      ledCount
  1..3   RGB
  4..    ledCount x 1-byte LED index
[zero pad]
```

Decoded example (the last upload, two colour groups):

```
a=2 b=36 brightness=100 bg=#ffffff groups=2
   33 leds #ff0000 [2,3,4,9..29,53..59,76,77]
   18 leds #ffbe0b [35..52]
```

Indices run 2..77, consistent with a strip of ~78 addressable LEDs.

The app's `DiyGraffitiV2.h()` builds a **richer** variant of this — 16-bit
counts, and a second index list for indices ≥ 256. The H66A0's uploads use the
compact 8-bit form above, which is what the bytes actually say; do not assume
the 16-bit form on this device.

### 5.4 Music effect (`0x41`)

**verified**, and this one decodes exactly against the APK source.

Header is two bytes: `41` then the **music code**. Payload is
`AbsNewMusicEffect.toBytes()`:

```
0        colourCount
1        colourCount x 3 bytes RGB
n        fade      (0 / 1)
n+1      piece
n+2      speed
n+3      pieceOffMin
n+4      pieceOffMax     (= max(pieceOffMin, piece/2))
```

The single capture 2 upload:

```
musicCode=52  colors=[#ff0000 #ff7f00 #ffff00 #00ff00 #0000ff #00ffff #8b00ff]
fade=0 piece=27 speed=35 pieceOffMin=1 pieceOffMax=13
```

Every field checks out against `RgbicMusicGangQinJian`: code 52 is that class's
`getMusicCode()`, `speed=35` is its `def_speed`, `pieceOffMax = max(1, 27/2) =
13` is exactly the formula in `toBytes()`, and the seven colours are
`AbsNewMusicEffect.makeDefColors()` verbatim — red, orange, yellow, green,
blue, cyan, violet `(139,0,255)`.

The field meanings are per-effect: read the matching `AbsNewMusicEffect`
subclass (`RgbicMusicFenLi`, `RgbicMusicDuiJi`, `RgbicMusicHaiLang`, …).
`piece`/`pieceOff*` are segment counts and their ranges depend on the device's
IC count.

### 5.5 DIY effect (`0x04`)

**verified** framing, **from APK** for the field names.

Payload is `DiyProtocol.toBytes()`:

```
0        b
1        c
2        d
3        3 * colourCount
4        colourCount x 3 bytes RGB
p=4+len  2 * pairCount
p+1      pairCount x 2 bytes
```

The single capture 2 upload decodes as
`b0=255 b1=0 b2=50 colors=[#ff7f00 #00ff00] pairs=[(8,9),(2,2),(8,10),(2,2)]`,
activated by `33 05 0a fe 00 04` — DIY index `0xFE` = 254, matching
`DiyProtocolParseShare0x00.k()`, which constructs `new DiyProtocol(254, ...)`.

`b`, `c` and `d` are `DiyProtocolParseShare0x00`'s fields of the same names; the
app exposes them only as getters, so we have no better names for them, and the
pair list is its `List<int[]>` field `f`. One sample is not enough to say what
they control.

## 6. Model coverage

**Which SKUs use the V2 encrypted path?**

**The APK contains no static list, and we will not invent one.** We looked.
`supportEnc` is a field on a *cloud* response (`Request4SupportBleEncrypt`,
`Request4Support`), cached per device address and surfaced to the encryption
layer through `IEncryptionSupport.checkSupport(deviceAddress)`. There is no
SKU→encryption table anywhere in the dex.

What we can state:

* **H66A0 — verified.** Encryption version 2, AES-GCM path, controlled live.
* **H66A1** — same product line (TV Backlight 3 Pro), appears alongside H66A0 in
  every SKU list in the APK where H66A0 appears. **inferred**, untested.

That is the whole verified list. One device.

**The cheap way to widen it** is the `2b12` probe: connect, read
`00010203-0405-0607-0809-0a0b0c0d2b12`, report the bytes. One read, no capture
rig, no rooted phone, no cloud account. `govee_v3.py -v` prints it during
connect. Anything reporting version 2 uses the scheme in `PROTOCOL.md`;
anything reporting 0, or with no such characteristic, is plaintext.

If the advertisement parse in §3.5 is right, an even cheaper check is a passive
BLE scan: bit 6 of the flags byte in Govee's manufacturer data. We have not
confirmed that against a real scan record.

---

## 7. Summary for implementers

The short version, for someone adding a device to an integration:

1. Read `2b12`. Version 2 → wrap everything in AES-GCM (`PROTOCOL.md`).
   Anything else, or an error → write plaintext. Fail safe toward plaintext.
2. The SKU arrives from the device in the handshake plaintext. Use it; do not
   ask the user to pick a model.
3. Power `33 01`, brightness `33 04`, colour `33 05 <dialect>`. That is enough
   for a working light.
4. Read `aa 05` at connect to learn the colour dialect if the device is in a
   colour mode; `aa a5` or `aa 40` for segment count; watch `aa 04` for
   brightness-scale evidence.
5. Subscribe to `2b10` and act on `ee 30 01` for real power state.
6. Scenes need the model JSON. Everything above does not — degrade to on/off,
   brightness and colour rather than failing setup.

---

## 8. What we have not captured

Neither capture is a complete exercise of the protocol. This section is the
honest inventory of what a client might still meet on the wire, from a sweep of
every frame builder in the APK — every class overriding `f()`/`g()`/`getValue()`
rather than inheriting `AbsSingleController`'s `generate20Bytes` versions.

### 8.1 Frame shapes

The sweep found **18** classes that build their own byte arrays. Most are
product-family specific (`h71xx`, `h705a`, `h7022`, `pact_h605b`,
`dreamcolorlightv1/v2`, `matter`, movie-feast, cube). In the **common**
`base2light` set that an H66A0 draws on, these are the shapes that exist:

| Shape | Status |
|---|---|
| 20-byte `generate20Bytes`, XOR/BCC checksum | the normal case (§1) |
| `0xA5` mic frames — variable length, **byte-sum** checksum | **verified**, §2.9 |
| `0xA3` multi-packet, 20-byte frames | **verified**, §5 |
| `0xA4` multi-packet, **MTU-sized** frames | never seen |
| `0xA6` multi-packet, MTU-sized, chunked into groups | never seen |
| `0xA1`/`0xA2` `MULTIPLE_WRITE`/`MULTIPLE_READ` | never seen |
| `0xAB`/`0xAC` multi-packet **read** (device → host) | never seen |
| `0xE719`/`0xE71A` encryption-layer fragmentation | never seen (needs a small MTU; `PROTOCOL.md` §7) |

The two MTU shapes are the ones most likely to bite. `Compose4DefWrite4Multi` —
the newer DIY/scene write path — builds them with
`MultipleControllerCommV1.makeSendBytesMtu((byte) 0xA4, cmd, data, mtu)` and
`makeSendBytesMtu0xA6(...)`, sized to the negotiated MTU rather than 20 bytes:

```
0xA4 first   [a4][00][00][01][total lo][total hi][cmd][data...][BCC]
0xA4 middle  [a4][n][n][data...][BCC]
0xA4 last    [a4][ff][ff][data...][BCC]      (short form: a4 ff ff <BCC>)
0xA6 first   [a6][00][00][01][.. 17-byte header, cmd at [16] ..][data...][BCC]
```

Note the index is duplicated across bytes 1 and 2, and the packet total is a
16-bit little-endian field — neither is true of `0xA3`. **Our H66A0 negotiated
an MTU of 247** (`020f02` → `03f700` in capture 2) and still used the 20-byte
`0xA3` path for every scene, DIY and music upload, so the MTU path is selected
by something other than MTU alone — `useMtuController()` and
`isBigDataEffect()` both return false for the controllers this device uses. It
is reachable, we just have not made it happen.

`decode_commands.py` handles the first three rows. It does **not** reassemble
`0xA4`, `0xA6`, `0xA1`/`0xA2` or the `0xAB`/`0xAC` read direction; those would
be reported as unknown, not silently mis-parsed.

`WlanController` also builds its own `[cmd][01][value][BCC]` frame, but its only
caller (`CmdWlanSwitch`) base64-encodes it for the **cloud/MQTT** passthrough
path, so it is not a BLE frame family. Listed here only so the next sweep does
not re-flag it.

### 8.2 Commands worth capturing next

`BleProtocolConstants` names 227 constants over 118 distinct command bytes. Most
belong to devices far outside this document. Filtering to what is plausibly on
an H66A0 — a TV backlight with a camera module — these are the gaps, in rough
order of value:

* ~~**`0x32` camera install check.**~~ **Closed** — §2.6.3. It answers `01 01`
  with the module attached and nothing at all without it, so the arrival of the
  frame is the signal. What the two payload bytes mean individually is still open.
* ~~**The `0xA9` video/AI surface with the camera plugged in.**~~ **Closed** —
  §2.6.3. Seven subs answer; `0x0b` and `0x11` also accept writes. What remains
  open inside it is smaller and sharper:
  * **`0x11`'s two bytes.** Observed `01 02`, once. Not named, deliberately.
  * **`0x04`, `0x0a`, `0x10` payloads** — 7, 6 and 15 bytes, read but not decoded.
  * **`0x01` accepts a write and does not apply it.** Worth retrying with an
    active HDMI signal.
  * **`0x08` and `0x0c` never answer**, and unlike `0x03`/`0x0e` we have no
    explanation for them.
* **`0x16` effect direction** plus the `value_set_direction_*` family — direction
  is a real user-facing control we have never seen encoded.
* **`0x27` set preview effect, `0x28` delete scene, `0x29` sort scene** — scene
  management beyond "activate".
* **`0x33` volume, `0x37` prompt tone, `0x35` without-interrupt,
  `0x36` worry-free-at-night, `0x13` night mode, `0x41` on/off memory** — simple
  settings, cheap to capture, each one frame.
* **`0xB1`/`0xB2` read / check secret key** — unexamined, and the only commands
  in the table that sound security-relevant.
* **A multi-packet *read*.** Every multi-packet frame we have is host → device.
  We have never seen the device send one, so the reassembly on that side is
  untested.

None of these are blockers for basic control — power, brightness, colour, scenes,
DIY and music are all covered. They are what would make the picture complete.
