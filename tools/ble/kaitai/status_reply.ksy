meta:
  id: status_reply
  title: Govee H617A "aa" status-reply envelope (decode-only)
  endian: le
  imports:
    - govee_segment_page
    - govee_common
doc: |
  H617A 20-byte status reply. The final byte is the XOR of bytes 0 through 18.
  Segment replies have five groups of three records and four validated-zero bytes.
seq:
  - id: header
    contents: [0xaa]
  - id: domain
    type: u1
    enum: aa_domain
  - id: body
    size: 17
    type:
      switch-on: domain
      cases:
        'aa_domain::power': power_body
        'aa_domain::brightness': brightness_body
        'aa_domain::colormode': colormode_body
        'aa_domain::fw_version': version_body
        'aa_domain::hw_version': hw_version_body
        'aa_domain::segments': govee_segment_page(15, 3, true)
        'aa_domain::multi_effect': multi_effect_body
        # Measured: aa20 -> "1.04.02", aa21 -> "1.03.08", NUL-terminated ASCII padded with
        # zeroes, the same shape fw_version carries.  The H6199 grammar already reads them
        # this way; without these cases the body falls through to raw bytes and the reader
        # raises AttributeError on .text.
        'aa_domain::subordinate_20': version_body
        'aa_domain::subordinate_21': version_body
        'aa_domain::camera_install': camera_install_body
        'aa_domain::ic_segment_count': ic_segment_count_body
        'aa_domain::display_setting': display_setting_body
        'aa_domain::relative_brightness': relative_brightness_body
  - id: checksum
    type: u1
enums:
  aa_domain:
    0x01: power
    0x04: brightness
    0x05: colormode
    0x06: fw_version
    0x07: hw_version
    0x20: subordinate_20
    0x21: subordinate_21
    0x32: camera_install
    0x40: ic_segment_count
    0xa3: multi_effect
    0xa5: segments
    0xa9: display_setting
    0xae: relative_brightness
  display_setting:
    0x01: video_sensitivity
    0x04: ai_action
    0x06: white_balance
    0x09: ai_update_status
    0x0a: black_screen_detection
    0x0b: black_border_removal
    0x10: ai_filter
    0x11: hdr_effect
    0x13: white_balance_calibrated
  color_mode:
    0x00: video
    0x15: static
    0x04: scene
    0x0a: diy
    0x13: music
types:
  multi_effect_body:
    doc: >
      Readback of the gradual-change boolean written by command_write opcode 0xa3. The
      value is persistent device state. H617A explicitly exposes no gradual-change
      capability, and paired physical comparisons found no visible behaviour for true.
    seq:
      - id: flag
        type: u1
      - id: padding
        type: u1
        valid: 0
        repeat: eos
  power_body:
    seq:
      - id: is_on
        type: u1
      - id: padding
        type: u1
        valid: 0
        repeat: eos
  brightness_body:
    seq:
      - id: brightness_pct
        type: u1
      - id: padding
        type: u1
        valid: 0
        repeat: eos
  colormode_body:
    seq:
      - id: mode
        type: u1
        enum: color_mode
      - id: mode_body
        size: 16
        type:
          switch-on: mode
          cases:
            'color_mode::video': cm_video
            'color_mode::static': cm_static
            'color_mode::scene': cm_scene
            'color_mode::diy': govee_common::diy_selector
            'color_mode::music': govee_common::music_selector
  cm_static:
    doc: |
      The static-colour read-back. Only `sub` is identified.

      The remainder was `padding` with `valid: 0` until an H66A0 answered
      `aa 05 15 00 19 64 00...` -- sub 0, then 25 and 100, then zeros. That failed the
      zero check, so the WHOLE frame was rejected and the colour-mode domain was never
      observed; the device then never completed a state refresh and its config entry sat
      in setup_retry reporting "unreachable", with every other register answering
      normally on the same connection.

      The two bytes are NOT identified and are deliberately not named. 25 and 100 look
      like percentages and that is exactly the sort of guess this file should not make;
      nothing reads them. The H6199's own static body is already opaque bytes for the
      same reason, so this matches the treatment its sibling grammar gives the same
      register rather than inventing a third convention.

      The cost is the zero check an H617A reply used to get. That check was never
      evidence about this family -- it encoded one model's observed shape as a rule for
      all of them.
    seq:
      - id: sub
        type: u1
      - id: opaque
        size-eos: true
  cm_scene:
    seq:
      - id: scene_id
        type: u2le
      - id: padding
        type: u1
        valid: 0
        repeat: eos
  version_body:
    seq:
      - id: text
        type: strz
        encoding: ASCII
      - id: padding
        type: u1
        valid: 0
        repeat: eos
  hw_version_body:
    seq:
      - id: prefix
        contents: [0x03]
      - id: text
        type: strz
        encoding: ASCII
      - id: padding
        type: u1
        valid: 0
        repeat: eos
  ic_segment_count_body:
    doc: |
      Answer to aa 40. Two values, not one. An H66A0 answered `00 5a 0e` on 2026-08-23:
      0x005a = 90 big-endian in [0:2], and 0x0e = 14 in [2]. The first is the IC count the
      app's own IcNumController name suggests; the second is the segment count, and 14 is
      confirmed twice over independently -- by paging aa a5 (4+4+4+2) and by the 0x3fff mask
      the Govee app itself writes for this model.

      Read [2] as "a segment count on this model", not as a settled field for the family.
      The H6199 answers 38 to the same query, and 38 was positively excluded as its app
      segment count, so a caller must decide per model whether to trust this byte -- see
      ModelProfile.segment_count_from_ic_probe.
    seq:
      - id: ic_count
        type: u2be
      - id: segment_count
        type: u1
      - id: padding
        type: u1
        valid: 0
        repeat: eos
  camera_install_body:
    doc: |
      Answer to aa 32. An H66A0 with the camera module attached replied 01 01 on
      2026-08-23; the same device with the module unplugged did not reply at all. So the
      ARRIVAL of this frame is the install signal. What the two bytes mean individually is
      not established -- there is no second observation to compare them against -- and
      they are deliberately left unnamed rather than guessed at.
    seq:
      - id: raw
        size-eos: true
  display_setting_body:
    doc: |
      Answer to aa a9 <sub>: the sub-command echoed back, a length, and that many values.
      Confirmed across seven sub-commands on an H66A0 on 2026-08-23 (01 -> len 1, 04 ->
      len 7, 09 -> len 1, 0a -> len 6, 0b -> len 1, 10 -> len 15, 11 -> len 2), each
      length agreeing with the bytes that followed it. The same shape the H6199 already
      uses for its own 0xa9 registers, arrived at here from the wire rather than copied.

      Only black_border_removal is given a typed payload. It is the one sub-command whose
      meaning is unambiguous (one byte, 0 or 1) AND whose write form was round-tripped on
      hardware. The rest stay raw on purpose: naming a field we have not proven is how a
      guess becomes a fact somebody later depends on.
    seq:
      - id: setting
        type: u1
        enum: display_setting
      - id: len
        type: u1
      - id: payload
        size: len
        type:
          switch-on: setting
          cases:
            'display_setting::black_border_removal': black_border_removal_payload
  black_border_removal_payload:
    seq:
      - id: is_on
        type: u1
  cm_video:
    doc: |
      Video mode ("DreamView") state, read back through `aa 05` while the device is in it.

      The same six body bytes the write carries -- see command_write.ksy::video_body_h66a0 --
      so a client can read the device's own settings and replay them to re-enter the mode
      without inventing values. Verified 2026-08-26: a live H66A0 in video mode answered
      `aa 05` with `00 08 32 00 02 64`, and the vendor app's writes carry the same six fields.

      Every byte named, from a capture of the vendor app moving each control plus the owner
      reading the screen back with a known configuration on 2026-08-27. The device answered
      `aa 05` with `00 01 08 3e 01 02 01` while the app showed: Game, picture preset Vivid,
      saturation 62%, sound effects on, softness ~1%.

        game_mode       0 = Movie, 1 = Game.
        picture_preset  0x08 | index. The app's order is 0 Solid, 1 Vivid, 2 Smooth,
                        3 Delicate; the capture stepped 08 09 0a 0b, exactly those four.
                        Bit 3 is REQUIRED -- written cleared, the device stores the value but
                        the app then shows no preset selected (tested 2026-08-27).
        saturation      0..100. Read back as 0x3e = 62 against a slider showing 62%.
        sound_effects   0/1. Read back as 1 with the toggle on, and in the capture it went
                        0 -> 1, the softness byte then moved four times, then back to 0.
        reserved        DISPUTED between the APK and observation. Read the whole note before
                        trusting either name for this byte or the last one.

                        The APK chain is now BYTECODE-VERIFIED, not decompiler-inferred. An
                        earlier note here guessed jadx had mangled these single-letter
                        accessors; baksmali disassembly proves it did not:
                            g()I -> iget field f     o(I)V -> iput field f
                            i()I -> iget field h     q(I)V -> iput field h
                        Both candidate pacts build the body as {0,d(),b(),e(),f(),g(),i()},
                        so g() lands here and i() lands last. SoundEffectViewInterface's
                        onSoftnessChange calls o() -> field f -> g() -> THIS byte, and both
                        pact_tvlightv2 and pact_tvlightv4 override changeWholeRlBrightness to
                        call q() -> field h -> i() -> the LAST byte. By the APK, this byte is
                        the sound-effect softness and the last is a whole relative brightness.

                        Observation says the opposite, three times: in the capture the last
                        byte moved four times while sound effects were on and this one never
                        moved; a device reporting "softness at max" held 0x64 in the last byte;
                        and with this byte written to 100 the app still showed softness ~50%
                        while the last byte held 54.

                        Both are explicable if the slider being moved in the capture was the
                        whole-brightness one rather than softness, and if the app's UI did not
                        re-read after an external BLE write. Supporting that: the owner
                        described a relative-brightness slider "currently set to 50%" at a
                        moment when the last byte read 54.

                        NOT RESOLVED, and the naming below deliberately follows the hardware
                        rather than the APK, because a control wired the other way would be one
                        the user cannot see working. One clean test settles it: move ONLY the
                        softness slider in the app, change nothing else, then read both bytes.
        softness        0..100. Read back as 1 against a slider the owner described as
                        "very low, like 0, 1 or 2%".

      NOTE: video mode and DreamView are DIFFERENT modes. A device in a DreamView group is not
      in video mode, and both screens offer their own Game/Movie, brightness, sound effects and
      saturation. This body is video mode's; DreamView's live in the 0x60 family.
    seq:
      - id: game_mode
        type: u1
        valid:
          max: 1
      - id: picture_preset
        type: u1
      - id: saturation
        type: u1
        valid:
          max: 100
      - id: sound_effects
        type: u1
        valid:
          max: 1
      - id: reserved
        type: u1
      - id: sound_effects_softness
        type: u1
        valid:
          max: 100
      - id: padding
        type: u1
        valid: 0
        repeat: eos

  relative_brightness_body:
    doc: |
      Per-edge relative brightness, the same six-slot shape the shared app parser reads and
      h6199_status_reply::relative_brightness_body already models.

      Modelled here on 2026-08-24 because an H66A0 answers this register too. It was NOT
      modelled on this schema before, so when supports_relative_brightness was turned on for
      that model the reply came back as raw bytes and the notify handler raised
      AttributeError on every poll -- inside bleak's callback, ~2000 times. Enabling a query
      whose reply only one schema can parse is the shape of mistake to watch for here.

      The query needs its 0x01 selector; a bare `aa ae` answers `00 00`, which is where the
      long-standing "reports zero zones" reading came from.
    seq:
      - id: selector
        contents: [0x01]
      - id: edge_count
        type: u1
        valid: 0x04
      - id: left_percent
        type: u1
      - id: top_percent
        type: u1
      - id: right_percent
        type: u1
      - id: bottom_percent
        type: u1
      - id: strip_left_percent
        type: u1
      - id: strip_right_percent
        type: u1
