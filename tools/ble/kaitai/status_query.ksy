meta:
  id: status_query
  title: Govee H617A "aa" status-query envelope
  endian: le
doc: |
  H617A 20-byte status query. The final byte is the XOR of bytes 0 through 18.
  Issue #286 AA0F reuses zero_body based on Android 7.6.01 LightNumController /
  AbsOnlyReadSingleController and direct H617A queries, not official-app captures.
  This route remains speculative; see speculative/h617a_control_payload.ksy.
  AA0501 is also produced by Android 7.6.01
  com/govee/base2light/ble/controller/AbsModeController.p(), inherited by
  dreamcolorlightv1/ble/ModeController on the H6102 goods-18 route (#115).
  Direct H617A queries answered both AA0500 and AA0501 (2026-09-16).
  This does not establish that AA0500 fails on H6102.
  H6102 #115 limit/gradual queries use the shared zero body: Android 7.6.01
  dreamcolorlightv1/ble/LimitController and Gradual4BleWifiController inherit
  AbsSingleController.p. Product authorization remains in the effective profile.
seq:
  - id: header
    contents: [0xaa]
  - id: domain
    type: u1
    enum: query_domain
  - id: body
    size: 17
    type:
      switch-on: domain
      cases:
        'query_domain::power': zero_body
        'query_domain::brightness': zero_body
        'query_domain::colour_mode': colour_mode_query_body
        'query_domain::firmware': zero_body
        'query_domain::hardware': hardware_query_body
        'query_domain::subordinate_20': zero_body
        'query_domain::subordinate_21': zero_body
        'query_domain::light_count': zero_body
        'query_domain::camera_install': zero_body
        'query_domain::ic_segment_count': zero_body
        'query_domain::limit': zero_body
        'query_domain::multi_effect': zero_body
        'query_domain::segments': segment_query_body
        'query_domain::display_setting': display_setting_query_body
        'query_domain::relative_brightness': relative_brightness_query_body
  - id: checksum
    type: u1
enums:
  query_domain:
    0x01: power
    0x04: brightness
    0x05: colour_mode
    0x06: firmware
    0x07: hardware
    0x0e: limit
    0x0f: light_count
    0x20: subordinate_20
    0x21: subordinate_21
    # A bare presence probe for the removable camera module. It answers only with the
    # module attached, which is what makes camera capabilities a runtime question.
    0x32: camera_install
    # 00 <ic count u16be> <app segment count>. The third byte is only trustworthy where it
    # has been cross-checked -- an H6199 answers 38 here and 38 is NOT its segment count.
    0x40: ic_segment_count
    0xa3: multi_effect
    0xa5: segments
    0xa9: display_setting
    0xae: relative_brightness
  display_setting:
    0x06: scalar_white_balance
types:
  colour_mode_query_body:
    seq:
      - id: selector
        type: u1
        valid:
          any-of: [0, 1]
      - id: zeros
        type: u1
        valid: 0
        repeat: eos
  display_setting_query_body:
    doc: |
      A bare read of one 0xa9 register: the sub-command byte and nothing else. Confirmed on an
      H66A0 on 2026-08-23, which answered subs 01, 04, 09, 0a, 0b, 10 and 11 in the
      setting/len/values shape of status_reply::display_setting_body.

      Issue 303 added a second copy of this type constrained to `scalar_white_balance`. Kept as
      one general type instead: the sub-command is the only field, and an H66A0 reads seven of
      them. Scalar white-balance readback is one such sub and is unaffected.
    seq:
      - id: setting
        type: u1
      - id: zeros
        type: u1
        valid: 0
        repeat: eos
  relative_brightness_query_body:
    doc: |
      Needs its 0x01 selector.  The bare form answers `00 00`, which is where an earlier
      "zero zones" reading came from -- the device was answering a question it had not been
      asked.  Confirmed on an H66A0 on 2026-08-24: `33 ae 01 04 3c 3c 3c 3c` read back as 60
      and `... 32 32 32 32` restored the 50 it started at.
    seq:
      - id: selector
        contents: [0x01]
      - id: zeros
        type: u1
        valid: 0
        repeat: eos
  zero_body:
    seq:
      - id: zeros
        type: u1
        valid: 0
        repeat: eos
  hardware_query_body:
    seq:
      - id: selector
        contents: [0x03]
      - id: zeros
        type: u1
        valid: 0
        repeat: eos
  segment_query_body:
    doc: Selects one of five three-segment reply groups.
    seq:
      - id: group
        type: u1
        valid:
          min: 1
          max: 5
      - id: zeros
        type: u1
        valid: 0
        repeat: eos
