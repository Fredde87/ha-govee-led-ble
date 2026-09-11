meta:
  id: govee_handshake
  title: Govee encryption-v2 0xE711 handshake layouts (decode-only)
  endian: be
doc: |
  The byte layouts of the 0xE711 session handshake, described apart from the cryptography that
  operates on them.  The AES-GCM seal and open stay in Python; what is here is where the fields
  sit, which is the part worth having beside the other wire definitions.

  Two structures, and the asymmetry between them is the thing to know: the REQUEST carries a
  tagLen byte after its IV and the RESPONSE does not.  So the response's additional
  authenticated data is 15 bytes rather than 16, and its ciphertext starts one byte earlier.
  Reading one layout as the other authenticates against the wrong AAD and fails with a tag
  error that says nothing about the cause.
types:
  handshake_request:
    doc: |
      `[E7][11][01][iv 12][tagLen][gcm(ct || tag)]`.  The AAD is the frame's own first 16 bytes,
      tagLen included.  The sealed payload is the 8-byte client ivKey.
    seq:
      - id: magic
        contents: [0xe7, 0x11]
      - id: direction
        contents: [0x01]
      - id: iv
        size: 12
      - id: tag_len
        type: u1
      - id: sealed
        size-eos: true
  handshake_response:
    doc: |
      `[E7][11][status][iv 12][gcm(ct || tag)]`.  No tagLen, so the AAD is the first 15 bytes.
      A non-zero status is the device refusing negotiation, and is reported as such rather than
      being decrypted -- the payload of a refusal has never been observed to carry anything.
    seq:
      - id: magic
        contents: [0xe7, 0x11]
      - id: status
        type: u1
      - id: iv
        size: 12
      - id: sealed
        size-eos: true
  handshake_plaintext:
    doc: |
      What the response's ciphertext opens to: 19 bytes, and every one of them accounted for.
      The device key is derived from the SKU and the MAC, both of which the device broadcasts in
      its advertisement, which is why no cloud call is needed anywhere in this path.

      The MAC is in WIRE order, which is the order the key derivation wants; it is not reversed
      here, and a caller wanting display order has to reverse it itself.
    seq:
      - id: device_iv_key
        size: 8
      - id: sku
        size: 5
        doc: ASCII, e.g. "H66A0".  Matches the SKU in the device's advertisement.
      - id: mac_wire_order
        size: 6
