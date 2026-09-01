# Govee BLE encrypted control protocols — **two generations**

Govee ships **two** BLE encryption schemes and the app treats both as current.
`BgcInfoReader.g()` accepts version 1 *or* 2; only `h()` is v2-specific.

| | **v1** (§10) | **v2** (§4–§5) |
|---|---|---|
| Handshake | `0xE7 0x01` + `0xE7 0x02`, two rounds | `0xE7 0x11`, one round |
| Handshake key | `K_COMM` | `K_HS` |
| Session key | sent by the device, `plaintext[2:18]` | derived: `AES-ECB(SKU‖MAC)` under `K_DEV` |
| Cipher | AES-128-ECB per block + RC4 tail | AES-128-GCM |
| Authentication | XOR checksum only | 16-byte GCM tag |
| Frame length | **preserved** — 20 bytes stays 20 | **expands** — 20 bytes becomes 40 |
| `2b12` marker | may be **absent entirely** | present, reports 2 |

Frame length is the cheapest way to tell them apart in a capture.

A device that offers **no `2b12` characteristic at all** is not therefore plaintext — the
H61F5 that forced v1 into view is exactly that shape. See §10.3 for the detection cascade
this implies.

Reverse engineered statically from **Govee Home 7.5.30** (`com.govee.home`,
versionCode 1097) and validated offline against a PacketLogger capture of the
iOS app driving a **TV Backlight 3 Pro (SKU H66A0)** with the camera module
unplugged.

**Result: the scheme comes apart completely, and needs no per-device secret.**
All keys are app-global constants shipped in the APK. `secretCode` is *not*
used by this layer, so the broken cloud endpoint is not a blocker.

Everything below is confirmed by decrypting a real capture: **99/99 frames
decrypt with a valid GCM tag and a valid legacy XOR checksum, 0 failures.**

---

## 1. Where the code lives

The crypto is **pure Java/Kotlin**, in the `com.govee.encryp` package
(`classes13.dex`). It is *not* native.

The arm64 split ships exactly one Govee-authored JNI surface —
`Java_com_govee_nativekey_CryptoNativeLib_nativeRsaKey{,Dev}` in
`libcryptonativekey.so` — which is RSA for the cloud API and unrelated to BLE.
Every other `.so` is third-party (ML Kit, ObjectBox, AndroidX, Conscrypt).
`libl68ae1757.so` is **Virbox Protector**, but it only exports `JNI_OnLoad` and
does not protect the BLE classes: the dex is unencrypted and decompiles cleanly.

Relevant classes:

| Class | Role |
|---|---|
| `com.govee.encryp.LibTools` | holds the three app-global keys |
| `com.govee.encryp.AesGcmUtils` | AES-GCM primitives |
| `com.govee.encryp.ble.Constants` | the GATT UUIDs |
| `com.govee.encryp.ble.Controller4AesGcm` | `0xE711` handshake frame build/parse |
| `com.govee.encryp.ble.EncryptionManagerV2` | session state, data encrypt/decrypt |
| `com.govee.encryp.ble.Safe` | AES-ECB helper used for key derivation |
| `com.govee.encryp.ble.BgcInfoReader` | reads the encryption-version marker |

`EncryptionUtils.registerEncryptionSupport` logs the library version:
`Ble E-V1.0.16_20260209_1741`.

---

## 2. GATT layout

Service `00010203-0405-0607-0809-0a0b0c0d1910`:

| Char | Handle (this device) | Use |
|---|---|---|
| `…2b10` | 0x0018 | notify — device → host |
| `…2b11` | 0x001c | write-without-response — host → device |
| `…2b12` | — | read — encryption-version marker |

`2b12` reads back `01 02 00 …`. `BgcInfoReader.d()` parses this as
`type=0x01 → encryptVersion = data[1]` — so **version 2**, which selects the
AES-GCM path described here. (`g()` treats version 1 or 2 as "encryption
supported"; `h()` is true only for version 2.)

The characteristic is **20 bytes** on this device, zero-padded after the two
meaningful ones: `0102` followed by eighteen `00`. Only `[0]` and `[1]` are read.

Connection setup, in order:

1. write `0x0200` to handle 0x000f (Service Changed indications)
2. write `0x0100` to the CCCD of `2b10` (handle 0x0019) to enable notifications
3. `0xE711` handshake (below)
4. encrypted data frames

**MTU matters.** `EncryptionManagerV2.j()` sets the single-frame path only when
`mtu > tagLen + 35` (i.e. `mtu > 51` for a 16-byte tag). Below that the app
falls back to a fragmented format (`0xE719` for the session key, `0xE71A` for
data, last fragment marked `0xFF`) — see §7. The app requests MTU 512, and the
capture uses the single-frame path throughout.

> **Trap for BlueZ clients — verified 2026-08-23.** Do not gate the handshake on
> the MTU your BLE library reports without checking what it means. `bleak`'s BlueZ
> backend returns the 23-byte ATT default — and emits a `UserWarning` — until its
> private `_acquire_mtu()` has run, which nothing in Home Assistant calls. On the
> same connection where `client.mtu_size` said **23**, calling `_acquire_mtu()`
> reported the true value: **512**. 40-byte writes had already been succeeding.
>
> A client that reads 23 and concludes "too small, fall back to plaintext" will
> therefore never encrypt anything on Linux, while looking entirely correct — and
> against a device like the H66A0, which ignores plaintext, that presents as a light
> that silently does nothing. Treat the ATT default as *unknown* rather than *small*,
> and let the handshake timeout be the real guard.

---

## 3. Keys

Three 16-byte AES keys are stored as string resources, each an AES-ECB/PKCS5
ciphertext (hex) decrypted under *another* plaintext string resource used
directly as a UTF-8 key. `LibTools` does this at runtime:

| Accessor | ciphertext res | key res | recovered value |
|---|---|---|---|
| `LibTools.a()` | `app_y_com` | `app_x_name` | `FC03783C7C42CB83E202A1643648AFF6` |
| `LibTools.b()` | `app_x_com` | `app_y_name` | `AE028B630BAE6ECC4BFF1B249E22F955` |
| `LibTools.c()` | `app_communication` | `app_session` | `4D616B696E674C696665536D61727465` |

The decrypted value is a 32-char hex *string*; `AESUtils.parseHexStr2Byte`
turns it into the 16 raw key bytes.

`LibTools.c()` is ASCII `"MakingLifeSmarte"` — Govee's slogan, truncated to 16
bytes. As well as being a useful sanity check that the extraction is correct, it
is **`K_COMM`, the key that protects the encryption-**v1** handshake** (§8).

> **Corrected 2026-08-25.** This paragraph previously ended "It is not used by
> this BLE path." That was wrong, and it was wrong in the most expensive
> direction: the key had already been recovered and printed here, and the one
> sentence next to it told every later reader to stop looking. v1 was then left
> uninvestigated until an H61F5 — a device with no `2b12` characteristic at all —
> ignored five sessions of plaintext probing. The value above was correct all
> along; only the claim about it was false.

**Version stability — verified 2026-08-25.** All three keys are byte-identical in Govee
Home **7.5.30** (16 July 2026) and **7.6.10** (21 August 2026), and so are the three string
resources they are decrypted from. That is a statement about those two builds on that date,
not a promise about future ones; re-check it with `tools/find_app_keys.py`, which locates the
material **by content** rather than by resource id (§3.1).

Call them:

* **K_HS = `FC03783C7C42CB83E202A1643648AFF6`** — protects the `0xE711` handshake
* **K_DEV = `AE028B630BAE6ECC4BFF1B249E22F955`** — derives the per-device key
* **K_COMM = `4D616B696E674C696665536D61727465`** — protects the v1 `0xE7 01`/`0xE7 02`
  handshake, and nothing else (§8)

Both are **app-global**: identical for every user and every device.

To reproduce (resource IDs from `com.govee.encryption.R$string`:
`app_x_com=0x7f120633`, `app_x_name=0x7f120634`, `app_y_com=0x7f120635`,
`app_y_name=0x7f120636`):

```python
AES.new(app_x_name.encode(), AES.MODE_ECB).decrypt(bytes.fromhex(app_y_com))  # → PKCS5 → hex str
```

---

### 3.1 Reproducing this on a future version

Use `tools/find_app_keys.py <resources.arsc>`. It searches for the ciphertexts and key
strings **by shape** and proves each pairing by decrypting it, rather than reading known
resource ids.

That distinction is not cosmetic. The first version of this extraction hardcoded ids
(`0x7f1201d4` and neighbours). Between 7.5.30 and 7.6.10 those ids **moved**, and the
hardcoded lookup did not fail — it returned German translation strings, which are perfectly
valid resources and completely wrong. Content survives renumbering; ids do not.

The same script also reports ciphertexts of the right shape that decrypt under none of the
key strings. Three such blobs exist in both builds. They are not BLE key material and are
left alone.

## 4. The `0xE711` handshake

### 4.1 Request (host → device, written to `2b11`, 40 bytes)

Built by `Controller4AesGcm.d()` via `g(ivKey)`:

```
off  size  field
0    1     0xE7    magic
1    1     0x11    command (17 = request session key)
2    1     0x01
3    12    IV      random, from SecureRandom
15   1     tagLen  GCM tag length in BYTES (0x10 = 16)
16   ..    AES-GCM(ciphertext || tag)
```

* key = **K_HS**
* nonce = bytes `[3:15]`
* **AAD = the frame's own first 16 bytes**, `frame[0:16]`
* plaintext = **8-byte client `ivKey`** — `SecureRandom` 12 bytes truncated to 8
  (`Arrays.copyOf(AesGcmUtils.f(), 8)`)

Total = `tagLen + 24` = 40 bytes for a 16-byte tag.

This explains the "random byte 3" in the capture: byte 3 is simply **IV[0]**.
There is no session id or length field there. Likewise `frame[15]` is always
`0x10` in the capture because iOS uses a 16-byte tag.

> Android negotiates the tag length at runtime (`AesGcmUtils.j()`): it probes
> 96-bit support and prefers a **12-byte** tag, falling back to 16. A 12-byte
> tag makes the request 36 bytes instead of 40. The `tagLen` byte tells the
> device which is in use, so both are valid on the wire.

### 4.2 Response (device → host, notify on `2b10`, 50 bytes)

Parsed by `Controller4AesGcm.h()`:

```
off  size  field
0    1     0xE7
1    1     0x11
2    1     status   (must be 0x00; non-zero = key negotiation failed)
3    12    IV
15   ..    AES-GCM(ciphertext || tag)
```

* key = **K_HS**
* nonce = bytes `[3:15]`
* **AAD = `frame[0:15]`** (15 bytes — note: *not* 16, unlike the request; there
  is no `tagLen` byte in the response)
* plaintext = **19 bytes**

Note there is **no `tagLen` field** in the response, so the ciphertext starts at
offset 15 rather than 16.

The 19-byte plaintext splits (`EncryptionManagerV2.l()`) as:

```
[0:8]    device ivKey   (8 bytes)
[8:13]   SKU            (5 bytes ASCII, e.g. "H66A0" = 48 36 36 41 30)
[13:19]  BLE MAC        (6 bytes, wire order = little-endian / reversed
                         relative to the usual AA:BB:CC:DD:EE:FF display form)
```

Observed on the test device: `sku="H66A0"`, and the 6 MAC bytes are the device's
BLE address in reverse byte order — whose last two bytes match the hex suffix in
the advertised name (`Govee_H66A0_XXXX`). The actual MAC and the key derived from
it are device-identifying and are kept out of this document; run
`decrypt_capture.py` locally to see them.

**Byte order matters for the next step — do not normalise these bytes.** Key
derivation consumes `plaintext[13:19]` exactly as it arrives on the wire. The
reference tools only reverse the bytes when *printing* a MAC for humans, so
"mac reversed" in their output means "shown in display order", not "reordered
before use".

### 4.3 Session key derivation

`EncryptionManagerV2.v()`:

```
devInfo   = SKU(5) || plaintext[13:19]       # 11 bytes; MAC in WIRE order
block     = devInfo zero-padded to 16 bytes
deviceKey = AES-ECB-Encrypt(block, key=K_DEV)   # NoPadding, single block
```

The MAC half is `plaintext[13:19]` verbatim — the little-endian/reversed form as
transmitted, **not** the display-order MAC. Flipping it here yields a valid-looking
16-byte key that fails every subsequent GCM tag check, which is an annoying way to
lose an afternoon.

`deviceKey` is the 16-byte AES-GCM key for all subsequent data frames.

**It depends only on SKU and MAC — both public.** Confirmed empirically: two
separate sessions in the capture produce byte-identical `deviceKey`
while the `ivKey`s differ. So the device
key can be computed offline from a BLE scan alone; the handshake is needed only
to exchange the two `ivKey` nonces.

No `secretCode`, no cloud call, no ECDH, no per-device provisioned secret.

---

## 5. Data frames

Both directions, on `2b11` (write) and `2b10` (notify):

```
off  size  field
0    4     counter, big-endian
4    ..    AES-GCM(ciphertext || tag)
```

* key = **deviceKey**
* **nonce = `ivKey(8) || counter(4)`** = 12 bytes
* **AAD = the 4 counter bytes**
* plaintext = **20 bytes** = the legacy Govee frame, unchanged

Each direction uses **its own `ivKey`**:

| Direction | ivKey |
|---|---|
| host → device | the **client** ivKey (plaintext of the request) |
| device → host | the **device** ivKey (plaintext[0:8] of the response) |

This is the one thing that is easy to get wrong: using the wrong side's `ivKey`
gives `InvalidTag` on every frame.

Counters increment independently per direction and reset each session. On the
wire the **host counter starts at 2** and the **device counter starts at 1**.

**Settled by live testing.** Starting the host counter at 2 is correct and is
accepted by the device, so this is no longer an open question. (The decompiled
`c()` initialises `q = 1` and post-increments, which would put the first host
frame at 1; `r()`/`s()` decompile only partially, so where the extra increment
happens internally is still unexplained — but it is moot, because the wire
behaviour is confirmed against real hardware.)

**Failed authentication does not advance the device's replay state.** During
live bring-up, three unsuccessful key attempts each sent counter 2, and the
device then accepted counter 2 again on the successful attempt. So the device
only advances its expected counter for frames that *pass* the GCM tag check —
a rejected frame costs nothing.

Two practical consequences:

* You do not need to guess how far a failed handshake advanced anything. Retry
  from the same counter.
* A client that resets cleanly per session — as the app does, and as
  `govee_v3.py` does — never has to reconcile counter state after an error.

With a 16-byte tag: 4 + 20 + 16 = **40 bytes**, matching the capture exactly.

### Why the brief thought notifies were 16 bytes

They aren't. The original transcription truncated them. Re-extracting the ATT
layer from the `.pklg` shows notifications are **50 bytes** (handshake response)
and **40 bytes** (data) — the same format as writes. There is no asymmetry to
explain.

---

## 6. The plaintext: the legacy protocol survives intact

Decrypted plaintext is the **classic 20-byte Govee frame**, unchanged:

```
[0]     header  0x33 = SET, 0xAA = GET/report, 0xEE = device-pushed event
[1]     command
[2:19]  payload
[19]    XOR of bytes 0..18
```

Every one of the 99 decrypted frames has a valid XOR checksum.

So the answer to the brief's hypothesis is: **20 bytes plaintext + 16-byte tag**,
and the old command language is completely intact underneath. The legacy writes
were being ignored by firmware only because they were unencrypted.

Commands seen:

| Frame | Meaning |
|---|---|
| `3301 00 …` | **power OFF** |
| `3301 01 …` | **power ON** |
| `3304 <0-100> …` | brightness (`3304 25` = 37) |
| `3305 15 01 …` | colour / colour temperature, RGBIC type-tagged dialect |
| `3309 …` | set time (`3309 17 02 04 02 01 01 00` = 23:02:04, Tuesday, UTC+1) |
| `aa01`, `aa04`, `aa05` | query power / brightness / mode |
| `aa06`, `aa07` | software version, device info (ASCII `1.00.21`, `3.07.01`) |
| `aa11`, `aa12` | sleep timer, wake-up alarm |
| `aa23`, `aaa3`, `aaa9`, `aaae` | timers, gradual change, video/AI settings, relative brightness |
| `aaa5 <page>` | per-segment colour readback, 4 segments per page |
| `ee30 01 …` | device-pushed light-status change |

**The full command language is documented separately in
[`COMMANDS.md`](COMMANDS.md)**, with payload layouts, per-model dialects,
runtime capability discovery, and a confidence marking on every entry.
`decode_commands.py` decodes this capture against that table (96 of 99 frames
named, 0 checksum failures).

Note the brief's counter labels were offset by a few frames (as it anticipated).
The decrypted bytes are the ground truth: the frame the brief labelled
"POWER ON" is `3301 00`, i.e. off, and the one labelled "set to blue" is the
2700 K colour-temperature command that preceded it.

---

## 6a. Connection lifetime: the device drops an idle link in under 15 seconds

**verified**, 2026-08-24, on an H66A0 over an encrypted session. A connection that
completes the handshake and then sits **idle** for 15 seconds is gone by the time the next
write is attempted — bleak raises `BleakError: Service Discovery has not been performed
yet`, which is what a link torn down underneath the client looks like from its side.

Found while testing something else: an experiment tried to separate "the device needs
settling time after connect" from "the client is sending too fast", and its 15-second
settle destroyed the connection it was measuring. Re-running the same test with the wait
filled by paced `aa 01` reads instead of a sleep kept the link alive indefinitely.

Two consequences for anyone building on this:

* **Any keepalive interval must be comfortably under 15 s.** Home Assistant's integration
  polls every 5 s, which is why this had never been noticed there.
* **Traffic, not time, is what holds the link.** The device is not timing out the session;
  it is timing out the *silence*. A client that wants a long-lived connection has to keep
  something on the wire.

The upper bound is not established — the drop is somewhere between "5 s of polling keeps it
alive" and "15 s of silence loses it", and nothing has been run to narrow it further.

## 7. Small-MTU fallback (not needed here, documented for completeness)

When `mtu <= tagLen + 35`, `Controller4AesGcm.b()`/`a()` fragment instead:

* session key request: `0xE7 0x19 …` (`ControllerProtocol.w = 25`), header is
  4 bytes (`E7 19 seq 02`), AAD is 17 bytes, and `[16]` carries `tagLen`
* data: `0xE7 0x1A …` (`ControllerProtocol.x = 26`)
* fragments are numbered; the final fragment is marked `0xFF`
* reassembly happens before decryption; the AAD is the first 7 (data) or 16
  (session key) bytes of the reassembled buffer

Any client that negotiates a normal modern MTU (≥ 52) never touches this.

---

## 8. Recovering the ivKeys without the handshake

**verified** — this is how `capture2.pklg` was decrypted; it has no `0xE711`
handshake at all (the capture was started while the app was already connected,
so the session frames begin at counters 0x30 / 0x28).

The two 8-byte `ivKey`s are freshly random per session — the two sessions in
`Govee Capture.pklg` use different ones — so a capture that misses the
handshake looks unrecoverable. It is not, because **the deviceKey does not
depend on the session**: it is `AES-ECB(KEY_DEVKEY, SKU || MAC)` (§3), and both
inputs are static per device.

With the key known, AES-GCM hands the nonce back. For a 12-byte IV:

```
J0  = IV || 00 00 00 01
H   = AES-Enc_K(0^128)
tag = GHASH_H(AAD, C) XOR AES-Enc_K(J0)
```

`K`, `AAD` (the 4 counter bytes), `C` and `tag` are all in the captured frame,
so `GHASH_H(AAD, C)` is computable and

```
J0 = AES-Dec_K( tag XOR GHASH_H(AAD, C) )
```

recovers the whole nonce from **one frame**. `IV = J0[0:12]`, and the `ivKey`
is `J0[0:8]`.

**It self-checks.** A correct recovery must come back shaped as
`ivKey(8) || counter(4, exactly as sent) || 00000001`. Eight bytes of structure
have to land right by construction, so a wrong deviceKey (wrong SKU or MAC)
fails visibly rather than producing plausible garbage — which also means you can
*search* for the SKU by trying candidates until one validates.

The MAC does not have to come from the handshake either: PacketLogger's own
type-`0x0A` note records carry the peer BD_ADDR, so it can be read straight out
of the same file. `mac_candidates()` does that.

`decrypt_capture.py` implements this as `recover_iv_key(frame, dev_key)` and
`session_keys(path, sku=...)`, and falls back to it automatically when no
handshake is present:

```
$ python3 decrypt_capture.py capture2.pklg
[no handshake in capture -- ivKeys recovered from the GCM tags]
[recovered]     client ivKey = <8 bytes, redacted>
[recovered]     device ivKey = <8 bytes, redacted>
[recovered]     deviceKey    = <16 bytes, redacted -- derived from this device's SKU+MAC>
...
Decrypted OK: 1022   Failed: 0
```

This is not a weakness in GCM — GCM never promised nonce secrecy, and the nonce
is not supposed to be a secret. It matters here only because Govee's scheme
leans on the ivKey as if it were one. Practically it means **any capture of a
Govee v3 session is decryptable, whether or not the handshake was recorded.**

---

## 9. Security note (for the record)

The handshake key is a global constant compiled into the app, and the per-device
key is a deterministic AES-ECB encryption of `SKU || MAC` — both of which are
broadcast in the clear by the device itself. So anyone in radio range who has
looked at the APK can derive the key for any Govee device using this scheme and
issue authenticated commands. This is obfuscation, not access control. §8 adds
that past traffic is decryptable too, even without the session handshake.

That is stated only to document what the scheme does and does not provide. It is
also precisely why local control is achievable without vendor cooperation.


---

## 10. Encryption v1 — the earlier generation (`0xE7 0x01` / `0xE7 0x02`)

**Verified 2026-08-25** against a PacketLogger capture of the vendor app driving an **H61F5**:
149 of 153 frames decrypt to a valid XOR checksum under the recovered session key, and the
remaining four *are* the handshake, under `K_COMM`. Every frame is accounted for.

Sources: `com.govee.encryp.ble.Safe` and `com.govee.encryp.ble.Controller4Aes`.

### 10.1 The cipher — length-preserving, and that is the tell

`Safe.d()` (encrypt) and `Safe.b()` (decrypt) split the frame:

* every whole **16-byte block** through **AES-128-ECB/NoPadding**
* the trailing `len % 16` bytes XORed with an **RC4** keystream under the *same* key
  (`Safe.f()` is the standard KSA, `Safe.g()` the PRGA)

A 20-byte command therefore goes out as `AES-ECB(bytes 0–15) ‖ RC4(bytes 16–19)` and stays
**20 bytes**, where v2 seals the same command into 40.

> **The RC4 tail is a constant.** RC4 is re-keyed for every frame, so the keystream covering
> bytes 16–19 never advances. Any two frames whose plaintext pads with zeros are **identical
> in bytes 16–18**. In the capture that showed up as a `9a 89 76` tail repeating across 62
> frames, and it is what identified the scheme *before* its key was known. It also means the
> tail leaks plaintext: XOR two frames and the padding cancels.

### 10.2 The handshake — two rounds

```
HOST>  Safe.d( [E7][01][random pad to 18][XOR checksum], K_COMM )     Controller4Aes.e()
<DEV   Safe.d( [E7][01][  session key, 16 bytes  ][cksum], K_COMM )   Controller4Aes.g()
HOST>  Safe.d( [E7][02][random pad to 18][XOR checksum], K_COMM )     Controller4Aes.f()
<DEV   Safe.d( [E7][02][ … ][cksum], K_COMM )                         Controller4Aes.h()
```

The **session key is `plaintext[2:18]`** of the first reply — sent by the device, not derived.
That is the sharpest difference from v2, where the per-device key is computed from the SKU and
MAC and never crosses the air. Every later frame uses the same transform under that key.

`Controller4Aes.a()` builds the frames and fills bytes 2..18 with `Random.nextInt` rather than
zeros; nothing depends on the padding being unpredictable, and the checksum is at byte 19.

The confirm round is not load-bearing — the key arrived in the previous frame — but the app
never skips it.

### 10.3 Detecting which scheme a device wants

The `2b12` marker **cannot** carry this decision alone. `BgcInfoReader.a()` sets its status to
3 and leaves `encryptVersion` at **0** when the characteristic is missing, which is
indistinguishable from a genuinely plaintext device. An H61F5 has no `2b12` at all.

Getting this wrong is not a benign fallback. A v1 device **accepts a plaintext write at the
ATT layer and acknowledges it**, then does nothing: the light connects, its entities populate,
every command reports success and the hardware never moves. There is no error anywhere to
diagnose from.

So the cascade has to end in a probe:

```
2b12 reports version 2   ->  v2
otherwise                ->  send the 0xE7 01 request; v1 if it answers
otherwise                ->  plaintext
```

The v1 attempt must fail safe to plaintext on silence, exactly as the v2 probe does. Silence
is the *expected* answer on every legacy device, so it costs one frame and a short timeout —
a real v1 device answered in **29 ms** — and the result is worth caching per device, since a
device's encryption generation is a property of its firmware rather than of the connection.

### 10.4 Security note

v1 is materially weaker than v2 and should not be mistaken for a security boundary. ECB leaks
block equality; the RC4 tail reuses one keystream for the life of the key; there is no
authentication beyond an XOR checksum, so any frame can be modified undetectably by anyone who
can compute the transform; and the session key is transmitted under an **app-global constant**
compiled into a public APK, so recovering it needs only a capture of the handshake. Everything
in §9 applies here with less margin.
