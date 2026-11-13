use image::{Rgba, RgbaImage};
use sha2::{Digest, Sha256};
use stegacode::{capacity, decode, encode, inspect, validate_filename, Error};

fn cover() -> RgbaImage {
    RgbaImage::from_fn(64, 64, |x, y| Rgba([x as u8, y as u8, 100, (x + y) as u8]))
}

// Write wire-format bytes independently of the codec, to exercise hostile inputs.
fn set_byte(image: &mut RgbaImage, offset: usize, byte: u8) {
    for bit in 0..8 {
        let index = offset * 8 + bit;
        image.as_mut()[(index / 3) * 4 + index % 3] =
            (image.as_raw()[(index / 3) * 4 + index % 3] & !1) | ((byte >> bit) & 1);
    }
}

fn crafted_plaintext(name: &[u8], data: &[u8]) -> RgbaImage {
    let mut packet = b"STEGACOD\x01\x00".to_vec();
    packet.extend_from_slice(&(name.len() as u16).to_be_bytes());
    packet.extend_from_slice(&(data.len() as u64).to_be_bytes());
    packet.extend_from_slice(name);
    packet.extend_from_slice(data);
    packet.extend_from_slice(&Sha256::digest(&packet));
    let mut image = cover();
    for (offset, byte) in packet.iter().enumerate() {
        set_byte(&mut image, offset, *byte);
    }
    image
}

#[test]
fn round_trip_every_byte_across_rows_preserves_alpha() {
    let mut image = cover();
    let original = image.clone();
    let data: Vec<u8> = (0..=255).cycle().take(1024).collect();
    encode(&mut image, &data, "秘密.bin", None).unwrap();
    let decoded = decode(&image, None).unwrap();
    assert_eq!(decoded.name, "秘密.bin");
    assert_eq!(decoded.data, data);
    for (before, after) in original.pixels().zip(image.pixels()) {
        assert_eq!(before[3], after[3]);
        for channel in 0..3 {
            assert!(before[channel].abs_diff(after[channel]) <= 1);
        }
    }
}

#[test]
fn empty_file_round_trip() {
    let mut image = cover();
    encode(&mut image, b"", "empty.txt", None).unwrap();
    assert_eq!(decode(&image, None).unwrap().data, b"");
}

#[test]
fn exact_capacity_and_one_byte_over_in_both_modes() {
    for password in [None, Some(b"test password".as_slice())] {
        let mut image = cover();
        let name = "x".repeat(255);
        let max = capacity(&image, &name, password.is_some()).unwrap();
        let overhead = if password.is_some() { 76 } else { 52 };
        assert_eq!(max, 64 * 64 * 3 / 8 - overhead - name.len());
        let original = image.clone();
        assert!(matches!(
            encode(&mut image, &vec![1; max + 1], &name, password),
            Err(Error::CapacityExceeded { .. })
        ));
        assert_eq!(image, original);
        encode(&mut image, &vec![255; max], &name, password).unwrap();
        assert_eq!(decode(&image, password).unwrap().data, vec![255; max]);
    }
}

#[test]
fn zero_and_tiny_images_return_errors() {
    for (width, height) in [(0, 0), (1, 1), (2, 2), (7, 7)] {
        let mut image = RgbaImage::new(width, height);
        assert!(matches!(
            capacity(&image, "x", false),
            Err(Error::ImageTooSmall { .. })
        ));
        assert!(encode(&mut image, b"", "x", None).is_err());
        assert!(decode(&image, None).is_err());
    }
}

#[test]
fn capacity_handles_partial_bytes_and_an_empty_payload_at_the_limit() {
    for width in 1..32 {
        for height in 1..16 {
            let mut image = RgbaImage::new(width, height);
            let raw = (width * height * 3 / 8) as usize;
            match capacity(&image, "x", false) {
                Ok(max) => {
                    assert_eq!(max, raw - 53);
                    encode(&mut image, &vec![0; max], "x", None).unwrap();
                    assert_eq!(decode(&image, None).unwrap().data.len(), max);
                }
                Err(Error::ImageTooSmall { .. }) => assert!(raw < 53),
                other => panic!("unexpected capacity result: {other:?}"),
            }
        }
    }
}

#[test]
fn rejects_unsafe_and_nonportable_filenames() {
    for name in [
        "",
        ".",
        "..",
        "../out",
        "a/b",
        "a\\b",
        "/out",
        "C:out",
        "x\0",
        "a\nx",
        "NUL",
        "CON .txt",
        "CONIN$",
        "conout$",
        "con.txt",
        "COM1",
        "lpt9.txt",
        "COM¹.txt",
        "end.",
        "end ",
        "a?b",
        "a*b",
        "a|b",
    ] {
        assert!(validate_filename(name).is_err(), "accepted {name:?}");
        if !name.is_empty() {
            assert!(
                matches!(
                    decode(&crafted_plaintext(name.as_bytes(), b"data"), None),
                    Err(Error::InvalidFilename)
                ),
                "decoded {name:?}"
            );
        }
    }
    assert!(validate_filename(&"a".repeat(256)).is_err());
    assert!(validate_filename("report 2026.txt").is_ok());
    assert!(validate_filename(".hidden").is_ok());
    assert!(matches!(
        decode(&crafted_plaintext(&[255], b"data"), None),
        Err(Error::InvalidFilename)
    ));
}

#[test]
fn ordinary_and_legacy_images_are_rejected() {
    assert!(matches!(
        decode(&cover(), None),
        Err(Error::InvalidFormat(_))
    ));
    assert!(matches!(
        decode(&RgbaImage::new(64, 64), None),
        Err(Error::InvalidFormat(_))
    ));
}

#[test]
fn rejects_bad_version_flags_and_lengths_before_reading_body() {
    for (offset, value) in [(8, 2), (9, 2), (10, 255), (11, 0), (12, 255), (19, 255)] {
        let mut image = crafted_plaintext(b"x", b"data");
        set_byte(&mut image, offset, value);
        assert!(decode(&image, None).is_err(), "accepted offset {offset}");
    }
    let mut image = crafted_plaintext(b"x", b"data");
    for offset in 12..20 {
        set_byte(&mut image, offset, 255);
    }
    assert!(matches!(inspect(&image), Err(Error::InvalidFormat(_))));
}

#[test]
fn detects_plaintext_data_and_header_corruption() {
    let mut image = crafted_plaintext(b"x", b"data");
    set_byte(&mut image, 21, b'X');
    assert!(matches!(
        decode(&image, None),
        Err(Error::IntegrityCheckFailed)
    ));
    let mut image = crafted_plaintext(b"x", b"data");
    set_byte(&mut image, 19, 3);
    assert!(matches!(
        decode(&image, None),
        Err(Error::IntegrityCheckFailed)
    ));
}

#[test]
fn encrypted_round_trip_and_password_errors() {
    let mut image = cover();
    encode(
        &mut image,
        b"confidential",
        "secret.txt",
        Some(b"correct password"),
    )
    .unwrap();
    assert!(inspect(&image).unwrap().encrypted);
    assert!(matches!(decode(&image, None), Err(Error::PasswordRequired)));
    assert!(matches!(
        decode(&image, Some(b"wrong password")),
        Err(Error::AuthenticationFailed)
    ));
    assert!(matches!(
        decode(&image, Some(b"")),
        Err(Error::EmptyPassword)
    ));
    let decoded = decode(&image, Some(b"correct password")).unwrap();
    assert_eq!(decoded.name, "secret.txt");
    assert_eq!(decoded.data, b"confidential");
}

#[test]
fn encrypted_metadata_nonce_salt_and_ciphertext_are_authenticated() {
    let mut image = cover();
    encode(
        &mut image,
        b"confidential",
        "secret.txt",
        Some(b"test password"),
    )
    .unwrap();
    for offset in [11, 19, 20, 36, 60, 85] {
        let mut corrupted = image.clone();
        // Toggle the first bit of this encoded byte.
        let index = offset * 8;
        corrupted.as_mut()[(index / 3) * 4 + index % 3] ^= 1;
        assert!(
            decode(&corrupted, Some(b"test password")).is_err(),
            "accepted tampering at {offset}"
        );
    }
}

#[test]
fn encryption_uses_fresh_randomness() {
    let mut first = cover();
    let mut second = cover();
    encode(&mut first, b"data", "x", Some(b"password")).unwrap();
    encode(&mut second, b"data", "x", Some(b"password")).unwrap();
    assert_ne!(first, second);
    assert_eq!(
        decode(&first, Some(b"password")).unwrap(),
        decode(&second, Some(b"password")).unwrap()
    );
}

#[test]
fn rejects_empty_encryption_password_without_modifying_image() {
    let mut image = cover();
    let original = image.clone();
    assert!(matches!(
        encode(&mut image, b"data", "x", Some(b"")),
        Err(Error::EmptyPassword)
    ));
    assert_eq!(image, original);
}

#[test]
fn explicit_password_cannot_silently_decode_plaintext() {
    let image = crafted_plaintext(b"x", b"data");
    assert!(matches!(
        decode(&image, Some(b"password")),
        Err(Error::UnexpectedPassword)
    ));
}
