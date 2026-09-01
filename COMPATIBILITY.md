# Compatibility

What each device we have tested actually reports. The point of this table is that
every row is a *measurement*, not an extrapolation from a model number.

All values were read from the device itself — over a decrypted session, or from
Home Assistant's Bluetooth scanner — on the date given. No BLE address, WiFi MAC
or session key appears here; those identify a physical unit and are deliberately
withheld.

## The `2b12` probe

`2b12` is the encryption-version marker, and it is the compatibility test this
project publishes. Read it and:

* `01 02 …` → **encryption v2**, the AES-GCM scheme (`PROTOCOL.md` §4–§5)
* `01 01 …` → encryption v1 — the app accepts this, though no device here reports it
* **characteristic absent** → **inconclusive, not "plaintext"**

That last case is the one that matters and it is not theoretical: H61F5 has no
`2b12` characteristic and is encrypted regardless. A client that reads "absent" as
"plaintext" will send frames the device acknowledges at the ATT layer and silently
ignores. See `PROTOCOL.md` §10.3 for the cascade that resolves it.

## Tested devices

| SKU | Encryption | `2b12` | pactType / pactCode | Firmware (`aa 06`) | Hardware (`aa 07 03`) | Tested |
|---|---|---|---|---|---|---|
| **H66A0** | v2 (AES-GCM) | `01 02 00 …` | 2 / 1 | `1.00.21` | `3.07.01` | 2026-08-23 |
| **H1A42** | v2 (AES-GCM) | `01 02 00 …` | 1 / 2 | `1.01.07` | `3.08.01` | 2026-08-25 |
| **H61F5** | **v1 (AES-ECB + RC4)** | **absent** | 3 / 1 | not read¹ | not read¹ | 2026-08-25 |
| H617A | plaintext | absent | — | — | — | — |
| H6199 | plaintext | absent | — | — | — | — |

¹ H61F5 answers `aa 06` and `aa 07` in the vendor app's own capture, so the
queries exist on it; this project has not yet driven a v1 session against it to
read them directly.

## Notes per device

**H66A0** — TV Backlight 3 Pro. 14 segments, page stride 4, camera module
optional and removable. The development device for most of `COMMANDS.md`.

**H1A42** — 5 segments, page stride 4, brightness scale 0–100, no camera, no video
registers, no relative brightness. Absent from Govee Home 7.5.30 entirely and
present in 7.6.10 as goodsType **400** — but ONLY in the new Kotlin-multiplatform
scene layer (`H1A42SceneConfig`, `KmpSceneConfigRegistry`, `KmpGoodsType`), with no
legacy pact package anywhere in the APK. So its pact stays `generic`, and anything
the pact packages would normally answer had to be measured instead.

Scenes and music were both settled on hardware on 2026-08-27. **Scenes: 159 of the
161 effects Govee publishes for the SKU**, each uploaded, activated and confirmed by
`aa 05` reading its own code back; codes **42 and 43 are refused by the device** and
are excluded. Activation is `33 05 04 <code LE16>` — the H617A/H66A0 two-byte form,
taken from this device's own capture rather than from the config. **Music: eight ids
of the 116 in the registry** — `03` Rhythm, `04` Spectrum, `05` Energic, `06`
Rolling, `84` Splash, `85` Spring, `92` Ripple, `a3` Orbit. The whole `0x30–0x3b`
block the H66A0 runs is refused here, and the classic block is not contiguous either
(`00–02` and `07–14` refused), so neither set was derivable — only a sweep answers.

**H61F5** — the device that revealed encryption v1. Advertises with the encryption
bit set but exposes no `2b12`. Ignores plaintext completely: ten `aa` queries and
two `33` commands across five sessions were all acknowledged at the ATT layer and
none was ever acted on.

## What the advertisement can and cannot tell you

`pactType` and `pactCode` are readable **passively**, without connecting, from the
manufacturer-data element — verified against the app's own parser
(`COMMANDS.md` §3.5). They are genuinely useful and better than the flags byte,
which is `0x43` on all three devices and so discriminates nothing.

But they are **not a model identifier**. The app consumes them scoped by
`goodsType`, which is a cloud field and is not in the advertisement. Three devices
here give three distinct pairs; that is not evidence the pair is unique, and it
should not be used as a discovery key.

## Contributing a device

Useful readings, in order of value: the `2b12` result (or that the characteristic
is absent), the advertised manufacturer data, `aa 40` (IC and segment counts),
`aa a5 01`/`02` (page stride — count the non-zero slots), `aa 04` (brightness
scale), and `aa 06`/`aa 07 03` (firmware and hardware).

**`aa 07` needs its `0x03` selector.** A bare `aa 07` returns silence, which reads
exactly like "not supported" and is not. `COMMANDS.md` §2.6 has the full warning;
it has produced a false negative twice.
