# StegaCode

A Rust CLI and library for hiding files in PNG images, with optional password encryption.

StegaCode stores one bit in each RGB channel and preserves alpha. It accepts PNG or JPEG cover images and always writes lossless PNG output. The `capacity` command reports the exact space available before encoding.

**Version 0.2 introduces format v1 and the lowercase `stegacode` executable. Old, unversioned images are unsupported.** Recover those files with the original 0.1 source before upgrading, then re-encode them with this version.

## Install

With a current stable Rust toolchain:

```bash
git clone https://github.com/arncv/StegaCode.git
cd StegaCode
cargo install --path . --locked
stegacode --help
```

To run from the checkout, use `cargo run --` in place of `stegacode`. To build without installing, use `cargo build --release --locked`; the binary is `target/release/stegacode` (`stegacode.exe` on Windows).

The release workflow builds archives for Linux x86_64, macOS Apple Silicon, and Windows x86_64, with SHA-256 checksum files. Published archives will appear on the [Releases page](https://github.com/arncv/StegaCode/releases). The workflow creates draft releases for maintainer review; it does not publish them automatically.

## Hide and recover a file

```bash
stegacode capacity --image cover.png --name secret.txt
stegacode encode --image cover.png --file secret.txt --output encoded.png
stegacode decode --image encoded.png --output recovered.txt
```

Omit `--output` when decoding to use the embedded basename in the current directory. Embedded filenames must be safe UTF-8 basenames of 1–255 bytes; paths, control characters, and Windows device names are rejected on every platform.

Both commands refuse to replace existing files unless you supply `--force`. Decoding validates integrity and the filename before creating output, including when `--force` is set. Output is prepared in a temporary file in the destination directory, so failed writes do not truncate an existing file. On Unix, newly created output files are private to the current user.

## Password encryption

```bash
stegacode capacity --image cover.png --name secret.txt --encrypted
stegacode encode --image cover.png --file secret.txt --output encrypted.png --encrypt
stegacode decode --image encrypted.png --output recovered.txt
```

Encoding prompts for a password and confirmation without echoing them. Decoding an encrypted image prompts automatically. Use a strong, unique passphrase; there is no password recovery.

For noninteractive use, supply a locally protected password file to either command:

```bash
stegacode encode --image cover.png --file secret.txt --output encrypted.png --password-file /secure/path/password
stegacode decode --image encrypted.png --output recovered.txt --password-file /secure/path/password
```

`--password-file` enables encryption during encoding. It reads password bytes and removes one trailing LF or CRLF; spaces remain significant. Empty passwords are rejected. Keep password files out of Git. Passwords are not accepted as command-line values.

## Security and limitations

- Plain mode includes SHA-256 to detect accidental corruption. Anyone can extract or replace an unencrypted payload and recompute its checksum.
- Encrypted mode derives a 256-bit key using Argon2id (19 MiB memory, two iterations, one lane). XChaCha20-Poly1305 authenticates the filename, file bytes, and public metadata. Every encoding uses a fresh 16-byte salt and 24-byte nonce from the operating system.
- Encryption protects contents, not the existence of hidden data. The public format identifier and sequential RGB bits are detectable. Image dimensions, payload length, and filename length remain public.
- Resizing, recompression, color conversion, and many social platforms destroy hidden bits. Preserve the original encoded PNG byte-for-byte. JPEG is supported as a cover input only.
- The decoder bounds all declared lengths against image capacity and rejects malformed or unsupported payloads. This project has not undergone an independent security audit.

See [the v1 format specification](docs/format.md) for the wire layout and capacity formula.

## Library

The library handles images and byte slices without reading or writing files:

```rust
use stegacode::{decode, encode};

fn main() -> Result<(), stegacode::Error> {
    let mut image = image::RgbaImage::new(64, 64);
    encode(&mut image, b"hello", "message.txt", None)?;
    let recovered = decode(&image, None)?;
    assert_eq!(recovered.data, b"hello");
    Ok(())
}
```

Pass `Some(password_bytes)` to enable encryption. `capacity` calculates available file space, and `inspect` validates public header fields without decrypting. `inspect` does not authenticate the payload; call `decode` to verify integrity.

## Development

```bash
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
```

Tests cover binary and empty files, exact capacity boundaries, tiny and ordinary images, malformed headers, unsafe names, corruption, password failures, saved-PNG round trips, and output protection. CI runs checks on Linux, macOS, and Windows. Commit `Cargo.lock` to keep application dependencies reproducible.

To prepare a release, update the package version and lockfile, merge the change, then push a matching tag such as `v0.2.0`. The release workflow verifies the tag against the package version, tests and builds all supported targets, and creates a draft release containing archives and checksums. Review and publish that release on GitHub when ready.

## License

[MIT](LICENSE)
