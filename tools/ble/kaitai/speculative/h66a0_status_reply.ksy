meta:
  id: h66a0_status_reply
  title: H66A0 "aa" status-reply envelope (speculative)
  endian: le
  imports:
    - /govee_segment_page
    - /status_reply
doc: |
  SPECULATIVE H66A0, issue #272 concern 3. All four official-app pages of one
  read are now supplied, each with a valid XOR checksum:
    aa a5 01 64e54444 64ffae54 64ffae54 64cf2e2e 24
    aa a5 02 64c72626 64c01f1f 64b91818 64b21111 01
    aa a5 03 64ba1919 64c32222 64cb2a2a 64d43333 6a
    aa a5 04 64dc3b3b 64e54444 00000000 00000000 32
  They confirm the four-slot brightness/RGB page and the 4+4+4+2 paging that
  reaches this device's fourteen segments; three per page would reach eleven.
  Unknowns: physical segment ordering and readback behaviour remain
  unqualified, and unused final-page slots have no established meaning or zero
  constraint. Preserve their raw octets. No other status domains or models are
  inferred, and this root is not a whole-family alias.

  Selected as a runtime root because the H66A0 profile names it as its
  status_grammar: its pages cannot be read through the H617A's three-record
  layout, which is the concern this file was written for.
seq:
  - id: header
    contents: [0xaa]
  - id: domain
    type: u1
    enum: status_domain
  - id: body
    size: 17
    type:
      switch-on: domain
      cases:
        # Every body except the segment page is byte-identical to the H617A's, so they are
        # referenced rather than copied: one definition, and a correction reaches both.
        'status_domain::power': status_reply::power_body
        'status_domain::brightness': status_reply::brightness_body
        'status_domain::colormode': status_reply::colormode_body
        'status_domain::fw_version': status_reply::version_body
        'status_domain::hw_version': status_reply::hw_version_body
        # Same NUL-padded ASCII version the H617A grammar carries; measured on hardware.
        'status_domain::subordinate_20': status_reply::version_body
        'status_domain::subordinate_21': status_reply::version_body
        'status_domain::camera_install': status_reply::camera_install_body
        'status_domain::ic_segment_count': status_reply::ic_segment_count_body
        'status_domain::display_setting': status_reply::display_setting_body
        'status_domain::relative_brightness': status_reply::relative_brightness_body
        'status_domain::multi_effect': status_reply::multi_effect_body
        # The one that differs, and the reason this root exists.
        'status_domain::segments': govee_segment_page(14, 4, false)
  - id: checksum
    type: u1
enums:
  status_domain:
    0x01: power
    0x04: brightness
    0x05: colormode
    0x06: fw_version
    0x07: hw_version
    0x0a: multi_effect
    0x20: subordinate_20
    0x21: subordinate_21
    0x32: camera_install
    0x40: ic_segment_count
    0xa5: segments
    0xa9: display_setting
    0xae: relative_brightness
