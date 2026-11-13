use std::{
    fs,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

use image::{RgbImage, Rgba, RgbaImage};
use tempfile::{tempdir, TempDir};

struct Fixture {
    dir: TempDir,
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            dir: tempdir().unwrap(),
        };
        RgbaImage::from_pixel(64, 64, Rgba([100, 120, 140, 255]))
            .save(fixture.path("cover.png"))
            .unwrap();
        fs::write(fixture.path("input.bin"), (0..=255).collect::<Vec<u8>>()).unwrap();
        fixture
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_stegacode"))
            .args(args)
            .current_dir(self.dir.path())
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    fn encode(&self) {
        success(self.run(&[
            "encode",
            "-i",
            "cover.png",
            "-f",
            "input.bin",
            "-o",
            "encoded.png",
        ]));
    }
}

fn success(output: Output) -> Output {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn failure(output: Output, message: &str) {
    assert!(!output.status.success(), "unexpected success");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(message),
        "expected {message:?}, got {stderr}"
    );
    assert!(!stderr.contains("panicked"), "{stderr}");
}

#[test]
fn cli_round_trip_saves_png_and_recovers_all_byte_values() {
    let fixture = Fixture::new();
    fixture.encode();
    success(fixture.run(&["decode", "-i", "encoded.png", "-o", "decoded.bin"]));
    assert_eq!(
        fs::read(fixture.path("decoded.bin")).unwrap(),
        fs::read(fixture.path("input.bin")).unwrap()
    );
    assert_eq!(
        &fs::read(fixture.path("encoded.png")).unwrap()[..8],
        b"\x89PNG\r\n\x1a\n"
    );
}

#[test]
fn default_decode_name_is_restored_in_working_directory() {
    let fixture = Fixture::new();
    fixture.encode();
    let restored = fixture.path("restored");
    fs::create_dir(&restored).unwrap();
    success(
        Command::new(env!("CARGO_BIN_EXE_stegacode"))
            .arg("decode")
            .arg("-i")
            .arg(fixture.path("encoded.png"))
            .current_dir(&restored)
            .output()
            .unwrap(),
    );
    assert_eq!(
        fs::read(restored.join("input.bin")).unwrap(),
        fs::read(fixture.path("input.bin")).unwrap()
    );
}

#[test]
fn jpeg_cover_is_supported_but_encoded_output_must_be_png() {
    let fixture = Fixture::new();
    RgbImage::new(64, 64)
        .save(fixture.path("cover.jpg"))
        .unwrap();
    success(fixture.run(&[
        "encode",
        "-i",
        "cover.jpg",
        "-f",
        "input.bin",
        "-o",
        "encoded.PNG",
    ]));
    success(fixture.run(&["decode", "-i", "encoded.PNG", "-o", "decoded.bin"]));
    assert_eq!(
        fs::read(fixture.path("decoded.bin")).unwrap(),
        fs::read(fixture.path("input.bin")).unwrap()
    );
    failure(
        fixture.run(&[
            "encode",
            "-i",
            "cover.png",
            "-f",
            "input.bin",
            "-o",
            "bad.jpg",
        ]),
        ".png",
    );
    assert!(!fixture.path("bad.jpg").exists());
}

#[test]
fn capacity_reports_exact_file_size_with_unicode_filename_and_encryption() {
    let fixture = Fixture::new();
    let name = "秘密.txt";
    for (encrypted, overhead) in [(false, 52), (true, 76)] {
        let mut args = vec!["capacity", "-i", "cover.png", "--name", name];
        if encrypted {
            args.push("--encrypted");
        }
        let output = success(fixture.run(&args));
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            format!("{} bytes\n", 64 * 64 * 3 / 8 - overhead - name.len())
        );
    }
}

#[test]
fn tiny_images_oversized_inputs_and_missing_files_fail_cleanly() {
    let fixture = Fixture::new();
    RgbaImage::new(1, 1).save(fixture.path("tiny.png")).unwrap();
    failure(
        fixture.run(&[
            "encode",
            "-i",
            "tiny.png",
            "-f",
            "input.bin",
            "-o",
            "no.png",
        ]),
        "too small",
    );
    fs::write(fixture.path("huge.bin"), vec![0; 10_000]).unwrap();
    failure(
        fixture.run(&[
            "encode",
            "-i",
            "cover.png",
            "-f",
            "huge.bin",
            "-o",
            "no.png",
        ]),
        "space for",
    );
    failure(
        fixture.run(&[
            "encode",
            "-i",
            "cover.png",
            "-f",
            "missing.bin",
            "-o",
            "no.png",
        ]),
        "cannot read input",
    );
    failure(
        fixture.run(&["decode", "-i", "missing.png", "-o", "no.bin"]),
        "cannot open image",
    );
    assert!(!fixture.path("no.png").exists());
    assert!(!fixture.path("no.bin").exists());
}

#[test]
fn ordinary_and_corrupted_images_create_no_output_even_with_force() {
    let fixture = Fixture::new();
    failure(
        fixture.run(&["decode", "-i", "cover.png", "-o", "absent.bin"]),
        "no v1 payload",
    );
    assert!(!fixture.path("absent.bin").exists());
    fixture.encode();
    let mut image = image::open(fixture.path("encoded.png")).unwrap().to_rgba8();
    // First data byte follows the 20-byte header and the 9-byte filename.
    let bit = (20 + "input.bin".len()) * 8;
    image.as_mut()[(bit / 3) * 4 + bit % 3] ^= 1;
    image.save(fixture.path("damaged.png")).unwrap();
    fs::write(fixture.path("keep.bin"), b"keep me").unwrap();
    failure(
        fixture.run(&["decode", "-i", "damaged.png", "-o", "keep.bin", "--force"]),
        "checksum failed",
    );
    assert_eq!(fs::read(fixture.path("keep.bin")).unwrap(), b"keep me");
}

#[test]
fn encode_and_decode_refuse_overwrites_without_force() {
    let fixture = Fixture::new();
    fs::write(fixture.path("encoded.png"), b"keep me").unwrap();
    failure(
        fixture.run(&[
            "encode",
            "-i",
            "cover.png",
            "-f",
            "input.bin",
            "-o",
            "encoded.png",
        ]),
        "--force",
    );
    assert_eq!(fs::read(fixture.path("encoded.png")).unwrap(), b"keep me");
    success(fixture.run(&[
        "encode",
        "-i",
        "cover.png",
        "-f",
        "input.bin",
        "-o",
        "encoded.png",
        "--force",
    ]));
    fs::write(fixture.path("decoded.bin"), b"keep me").unwrap();
    failure(
        fixture.run(&["decode", "-i", "encoded.png", "-o", "decoded.bin"]),
        "--force",
    );
    assert_eq!(fs::read(fixture.path("decoded.bin")).unwrap(), b"keep me");
    success(fixture.run(&[
        "decode",
        "-i",
        "encoded.png",
        "-o",
        "decoded.bin",
        "--force",
    ]));
    assert_eq!(
        fs::read(fixture.path("decoded.bin")).unwrap(),
        fs::read(fixture.path("input.bin")).unwrap()
    );
}

#[test]
fn password_file_round_trip_and_wrong_password_do_not_overwrite_output() {
    let fixture = Fixture::new();
    fs::write(fixture.path("password"), b"example test passphrase \r\n").unwrap();
    fs::write(fixture.path("wrong"), b"wrong password").unwrap();
    success(fixture.run(&[
        "encode",
        "-i",
        "cover.png",
        "-f",
        "input.bin",
        "-o",
        "encrypted.png",
        "--password-file",
        "password",
    ]));
    fs::write(fixture.path("decoded.bin"), b"keep me").unwrap();
    failure(
        fixture.run(&[
            "decode",
            "-i",
            "encrypted.png",
            "-o",
            "decoded.bin",
            "--password-file",
            "wrong",
            "--force",
        ]),
        "authentication failed",
    );
    assert_eq!(fs::read(fixture.path("decoded.bin")).unwrap(), b"keep me");
    // Equivalent password with LF also works; a trailing space is significant.
    fs::write(fixture.path("password"), b"example test passphrase \n").unwrap();
    success(fixture.run(&[
        "decode",
        "-i",
        "encrypted.png",
        "-o",
        "decoded.bin",
        "--password-file",
        "password",
        "--force",
    ]));
    assert_eq!(
        fs::read(fixture.path("decoded.bin")).unwrap(),
        fs::read(fixture.path("input.bin")).unwrap()
    );
    failure(
        fixture.run(&["decode", "-i", "encrypted.png", "-o", "absent.bin"]),
        "--password-file",
    );
    assert!(!fixture.path("absent.bin").exists());
}

#[test]
fn rejects_empty_passwords_and_noninteractive_prompts() {
    let fixture = Fixture::new();
    fs::write(fixture.path("empty"), b"\n").unwrap();
    failure(
        fixture.run(&[
            "encode",
            "-i",
            "cover.png",
            "-f",
            "input.bin",
            "-o",
            "no.png",
            "--password-file",
            "empty",
        ]),
        "cannot be empty",
    );
    failure(
        fixture.run(&[
            "encode",
            "-i",
            "cover.png",
            "-f",
            "input.bin",
            "-o",
            "no.png",
            "--encrypt",
        ]),
        "--password-file",
    );
    assert!(!fixture.path("no.png").exists());
}

#[test]
fn empty_file_can_be_encoded_and_decoded() {
    let fixture = Fixture::new();
    fs::write(fixture.path("empty.bin"), b"").unwrap();
    success(fixture.run(&[
        "encode",
        "-i",
        "cover.png",
        "-f",
        "empty.bin",
        "-o",
        "encoded.png",
    ]));
    success(fixture.run(&["decode", "-i", "encoded.png", "-o", "decoded.bin"]));
    assert!(fs::read(fixture.path("decoded.bin")).unwrap().is_empty());
}

#[test]
fn output_failure_does_not_leave_temporary_files() {
    let fixture = Fixture::new();
    fs::write(fixture.path("encoded.png"), b"keep me").unwrap();
    let before = fs::read_dir(fixture.dir.path()).unwrap().count();
    failure(
        fixture.run(&[
            "encode",
            "-i",
            "cover.png",
            "-f",
            "input.bin",
            "-o",
            "encoded.png",
        ]),
        "--force",
    );
    assert_eq!(fs::read_dir(fixture.dir.path()).unwrap().count(), before);
}

#[test]
fn malicious_embedded_path_is_rejected_even_with_an_explicit_output() {
    use sha2::{Digest, Sha256};

    let fixture = Fixture::new();
    let name = b"../escape.bin";
    let mut packet = b"STEGACOD\x01\x00".to_vec();
    packet.extend_from_slice(&(name.len() as u16).to_be_bytes());
    packet.extend_from_slice(&1_u64.to_be_bytes());
    packet.extend_from_slice(name);
    packet.push(42);
    packet.extend_from_slice(&Sha256::digest(&packet));
    let mut image = RgbaImage::new(64, 64);
    for (offset, byte) in packet.iter().enumerate() {
        for bit in 0..8 {
            let index = offset * 8 + bit;
            image.as_mut()[(index / 3) * 4 + index % 3] = (byte >> bit) & 1;
        }
    }
    image.save(fixture.path("malicious.png")).unwrap();
    let restored = fixture.path("restored");
    fs::create_dir(&restored).unwrap();
    failure(
        Command::new(env!("CARGO_BIN_EXE_stegacode"))
            .arg("decode")
            .arg("-i")
            .arg(fixture.path("malicious.png"))
            .current_dir(&restored)
            .output()
            .unwrap(),
        "safe UTF-8 basename",
    );
    assert!(!fixture.path("escape.bin").exists());
    failure(
        fixture.run(&["decode", "-i", "malicious.png", "-o", "explicit.bin"]),
        "safe UTF-8 basename",
    );
    assert!(!fixture.path("explicit.bin").exists());
}

#[cfg(unix)]
#[test]
fn symlink_destinations_are_not_followed() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    fixture.encode();
    fs::write(fixture.path("target.bin"), b"keep me").unwrap();
    symlink(fixture.path("target.bin"), fixture.path("link.bin")).unwrap();
    failure(
        fixture.run(&["decode", "-i", "encoded.png", "-o", "link.bin"]),
        "--force",
    );
    success(fixture.run(&["decode", "-i", "encoded.png", "-o", "link.bin", "--force"]));
    assert_eq!(fs::read(fixture.path("target.bin")).unwrap(), b"keep me");
    assert!(!fs::symlink_metadata(fixture.path("link.bin"))
        .unwrap()
        .file_type()
        .is_symlink());
    symlink(
        std::path::Path::new("missing.bin"),
        fixture.path("dangling.bin"),
    )
    .unwrap();
    failure(
        fixture.run(&["decode", "-i", "encoded.png", "-o", "dangling.bin"]),
        "--force",
    );
    assert!(!fixture.path("missing.bin").exists());
}
