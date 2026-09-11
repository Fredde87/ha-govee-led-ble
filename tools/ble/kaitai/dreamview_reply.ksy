meta:
  id: dreamview_reply
  title: Govee DreamView "aa 60" reply envelope (decode-only)
  endian: le
doc: |
  The replies a DreamView sync centre returns on 0x60.  Every one shares the same first two
  bytes, so the sub-command has to be checked as well as the header: reading one reply as
  another would silently produce plausible nonsense rather than an error.

  Two of them are digests rather than modelled bodies -- the group settings and the per-slot
  member table -- which is why the coordinator stores the frame whole and the readers are here.
seq:
  - id: header
    contents: [0xaa, 0x60]
  - id: sub
    type: u1
    enum: dreamview_sub
  - id: body
    size: 16
    type:
      switch-on: sub
      cases:
        'dreamview_sub::digest': digest_body
        'dreamview_sub::subdevice': subdevice_body
  - id: checksum
    type: u1
enums:
  dreamview_sub:
    0x05: subdevice
    0x0c: digest
types:
  digest_body:
    doc: |
      The group's settings in one frame.  Field order is correlated against the individual reads
      and writes in the same capture rather than assumed.  Two digests were taken, before and
      after the owner changed things:

          01 64 32 00 00 01 35        01 34 3b 01 01 01 37

        * brightness  0x64 -> 0x34 tracks `aa 60 03`, which answered 0x64 then `34 51 44`.
        * saturation  0x32 -> 0x3b tracks the saturation writes (`33 60 09`).
        * sound effects  0x00 -> 0x01 tracks them being switched on (`33 60 0b 01 ..`).
        * colour mode  0x00 -> 0x01 appears only after the two `33 60 0a` writes.
        * softness  0x35 -> 0x37 matches the last softness written before the second digest.
    seq:
      - id: is_on
        type: u1
      - id: brightness
        type: u1
      - id: saturation
        type: u1
      - id: sound_effects
        type: u1
      - id: colour_mode
        type: u1
      - id: unidentified
        size: 1
        doc: |
          0x01 in both snapshots and NOT the same-brightness toggle: `aa 60 04` read 0x01 at the
          first digest, same-brightness was switched off (`33 60 04 00`) before the second, and
          this byte stayed 0x01.  Left opaque rather than guessed; read `aa 60 04` for the real
          same-brightness state.
      - id: sound_effects_softness
        type: u1
      - id: trailing
        size-eos: true
        doc: Not observed carrying anything; kept opaque rather than validated as zero.
  subdevice_body:
    doc: |
      One connection state per sub-device slot, ten of them, matching the app's own maximum.
      0 = empty, 1 = connecting, 2 = connected.  Trailing zero slots are meaningful: the index
      of a state is the index of its sub-device, so they are not trimmed.
    seq:
      - id: slots
        type: u1
        repeat: expr
        repeat-expr: 10
      - id: trailing
        size-eos: true
