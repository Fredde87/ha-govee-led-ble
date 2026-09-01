# Govee BLE control protocol — two encryption generations

Notes from reverse-engineering how the Govee Home app talks to Govee lights over
Bluetooth LE, so that a local client can do the same without the cloud.

This started as one device and one scheme. It now covers **two encryption
generations** across **three SKUs in three different pact families**, which is
enough for the general shape to be visible rather than guessed at.

| | H617A / H6199 | **H66A0** | **H1A42** | **H61F5** |
|---|---|---|---|---|
| Encryption | plaintext | **v2** (AES-GCM) | **v2** | **v1** (AES-ECB + RC4) |
| pactType / pactCode | — | 2 / 1 | 1 / 2 | 3 / 1 |
| `2b12` marker | absent | `01 02` | `01 02` | **absent** |
| Segments / page stride | 15 / 3, 15 / 4 | 14 / 4 | 5 / 4 | — |

The thing worth taking from that table: **`2b12` being absent does not mean a
device is unencrypted.** H61F5 has no marker characteristic at all and is
encrypted anyway. Getting that wrong produces a light that connects, acknowledges
every command and never moves — see `PROTOCOL.md` §10.3.

## What is here

| File | Contents |
|---|---|
| `PROTOCOL.md` | Both encryption schemes: keys, handshakes, frame formats, the detection cascade |
| `COMMANDS.md` | The command and query language — the 20-byte frames themselves |
| `COMPATIBILITY.md` | Per-device results: encryption version, firmware, hardware, pact values |
| `tools/find_app_keys.py` | Recovers the three app-global keys from an APK's `resources.arsc` |

## The three app-global keys

Both schemes are protected by constants compiled into the public APK. They are
identical for every installation, are not per-device, and no `secretCode` or cloud
call is involved. `PROTOCOL.md` §3 has the values and how they are recovered.

**Version stability: the three keys and the three string resources they come from
are byte-identical in Govee Home 7.5.30 (16 July 2026) and 7.6.10 (21 August
2026).** That is a statement about those two builds on that date and nothing more.
Re-check it on any later version with `tools/find_app_keys.py`, which finds the
material by content rather than by resource id — the ids moved between exactly
those two builds, and a lookup by id returned plausible-looking nonsense rather
than failing.

## Reproducing

```
python3 tools/find_app_keys.py path/to/resources.arsc
```

Everything else in `PROTOCOL.md` and `COMMANDS.md` is marked with how it is known:
**verified** on hardware or in a decrypted capture, **device_accepted_write**,
**from APK**, or **inferred**. Claims at different confidence levels are not mixed,
and a single-device reading is labelled as one.

## Privacy

No BLE address, WiFi MAC, device UDID or derived session key appears in this
repository, and the packet captures behind these findings are not published. A
hardware address identifies one physical unit belonging to one person; the fact
that a value is easy to obtain is not a reason to publish it. Examples use
invented values that are structurally valid and unreachable.

## Scope

Independent interoperability research on devices we own. Not affiliated with
Govee. Encryption v1 in particular should not be mistaken for a security boundary
— `PROTOCOL.md` §10.4 says why.
