# StegaCode format v1

This format is introduced in StegaCode 0.2. It is incompatible with the original unversioned RGBA encoding. There is no automatic legacy fallback.

## Bit storage

Walk pixels from left to right, then top to bottom. Visit R, G, and B in that order, replacing each channel's least significant bit. Leave alpha untouched. Store each byte least significant bit first, continuing across pixel and row boundaries. Ignore unused trailing channels.

The total packet capacity is `floor(width * height * 3 / 8)` bytes.

## Header

All multibyte integers are unsigned and big endian.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | ASCII `STEGACOD` |
| 8 | 1 | Version, exactly `1` |
| 9 | 1 | Flags: `0` for plain, `1` for encrypted; other values rejected |
| 10 | 2 | UTF-8 filename length, 1–255 bytes |
| 12 | 8 | Original file size in bytes |

The 20-byte header is followed by one of the bodies below. Before allocating or processing the body, the decoder validates every declared length and the complete packet size against the image's capacity. Filenames are validated after integrity verification, even when the caller supplies a separate output path.

## Plain body

`header || filename || file_bytes || sha256`

The final 32-byte SHA-256 digest covers the header, filename, and file bytes. It detects accidental corruption and is not an authentication mechanism.

Maximum file size: `floor(width * height * 3 / 8) - 52 - filename_length`.

## Encrypted body

`header || salt || nonce || ciphertext_and_tag`

- Salt: 16 random bytes.
- Nonce: 24 random bytes, regenerated for every encoding.
- Key derivation: Argon2id v0x13, memory 19,456 KiB, iterations 2, parallelism 1, 32-byte output. The password is a byte string. KDF parameters are fixed for v1.
- Cipher: XChaCha20-Poly1305 with the derived 256-bit key and nonce.
- Plaintext: `filename || file_bytes`.
- Additional authenticated data: the complete `header || salt || nonce` prefix.
- Ciphertext length: `filename_length + file_size + 16`, including the authentication tag.

Maximum file size: `floor(width * height * 3 / 8) - 76 - filename_length`.

If the metadata cannot fit, capacity calculation returns an error. A zero-byte maximum permits an empty file. An empty password is invalid. An encrypted packet is never silently treated as plaintext, and a supplied password is rejected for plain packets.

## Compatibility

Unknown magic, versions, flags, invalid filenames, and impossible lengths are errors. The CLI writes PNG only; saving an encoded image through a lossy or transforming pipeline is unsupported. Future changes to the bit mapping, KDF, or packet layout require a new format version.
