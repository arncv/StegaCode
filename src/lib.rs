//! Versioned image steganography with optional authenticated password encryption.
//!
//! Data occupies RGB least significant bits; alpha is preserved. Save encoded images
//! as PNG. This format does not provide resistance to steganalysis or image editing.
//!
//! ```
//! let mut image = image::RgbaImage::new(64, 64);
//! stegacode::encode(&mut image, b"hello", "message.txt", None)?;
//! let recovered = stegacode::decode(&image, None)?;
//! assert_eq!(recovered.data, b"hello");
//! # Ok::<(), stegacode::Error>(())
//! ```

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use image::RgbaImage;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

mod pixels;

const MAGIC: &[u8; 8] = b"STEGACOD";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 20;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CHECKSUM_LEN: usize = 32;
const MAX_FILENAME_LEN: usize = 255;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("image is too small: format metadata needs {required} bytes, image holds {available}")]
    ImageTooSmall { required: usize, available: usize },
    #[error("payload needs {required} bytes, image has space for {available}")]
    CapacityExceeded { required: usize, available: usize },
    #[error("invalid or unsupported StegaCode image: {0}")]
    InvalidFormat(&'static str),
    #[error("unsupported StegaCode format version {0}")]
    UnsupportedVersion(u8),
    #[error("filename must be a safe UTF-8 basename of 1–255 bytes (no paths or reserved names)")]
    InvalidFilename,
    #[error("encrypted payload requires a password")]
    PasswordRequired,
    #[error("payload is not encrypted; omit the password")]
    UnexpectedPassword,
    #[error("password cannot be empty")]
    EmptyPassword,
    #[error("authentication failed: incorrect password or damaged payload")]
    AuthenticationFailed,
    #[error("payload checksum failed: image or metadata has been damaged")]
    IntegrityCheckFailed,
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("password key derivation failed")]
    KeyDerivationFailed,
    #[error("encryption failed")]
    EncryptionFailed,
}

/// Decoded filename and original file bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct FileData {
    pub name: String,
    pub data: Vec<u8>,
}

/// Validated public metadata. The filename itself is encrypted in encrypted mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadInfo {
    pub encrypted: bool,
    pub filename_bytes: usize,
    pub data_bytes: usize,
}

/// Reject paths, control characters, and names reserved by Windows on all platforms.
pub fn validate_filename(name: &str) -> Result<(), Error> {
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let reserved = matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|number| {
            matches!(
                number,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    });
    if name.is_empty()
        || name.len() > MAX_FILENAME_LEN
        || matches!(name, "." | "..")
        || name.ends_with(['.', ' '])
        || name
            .chars()
            .any(|ch| ch.is_control() || "/\\:<>\"|?*".contains(ch))
        || reserved
    {
        return Err(Error::InvalidFilename);
    }
    Ok(())
}

fn overhead(encrypted: bool) -> usize {
    HEADER_LEN
        + if encrypted {
            SALT_LEN + NONCE_LEN + TAG_LEN
        } else {
            CHECKSUM_LEN
        }
}

/// Exact maximum file size, accounting for filename, header and integrity overhead.
/// Returns an error when even an empty file with this name cannot fit.
pub fn capacity(image: &RgbaImage, name: &str, encrypted: bool) -> Result<usize, Error> {
    validate_filename(name)?;
    let available = pixels::capacity(image);
    let required = overhead(encrypted) + name.len();
    available.checked_sub(required).ok_or(Error::ImageTooSmall {
        required,
        available,
    })
}

fn key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    // Fixed parameters belong to format v1; no untrusted KDF work factors are read.
    let params = Params::new(19_456, 2, 1, Some(32)).map_err(|_| Error::KeyDerivationFailed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0; 32]);
    argon2
        .hash_password_into(password, salt, &mut *key)
        .map_err(|_| Error::KeyDerivationFailed)?;
    Ok(key)
}

/// Encode a file into RGB bits. `Some(password)` enables Argon2id + XChaCha20-Poly1305.
/// Invalid inputs are rejected before modifying the image.
pub fn encode(
    image: &mut RgbaImage,
    data: &[u8],
    name: &str,
    password: Option<&[u8]>,
) -> Result<(), Error> {
    let encrypted = password.is_some();
    let available = capacity(image, name, encrypted)?;
    if data.len() > available {
        return Err(Error::CapacityExceeded {
            required: data.len(),
            available,
        });
    }
    let data_len = u64::try_from(data.len())
        .map_err(|_| Error::InvalidFormat("file size is not representable"))?;
    let mut packet = Zeroizing::new(Vec::with_capacity(
        overhead(encrypted) + name.len() + data.len(),
    ));
    packet.extend_from_slice(MAGIC);
    packet.push(VERSION);
    packet.push(u8::from(encrypted));
    packet.extend_from_slice(&(name.len() as u16).to_be_bytes());
    packet.extend_from_slice(&data_len.to_be_bytes());
    let mut body = Zeroizing::new(Vec::with_capacity(name.len() + data.len()));
    body.extend_from_slice(name.as_bytes());
    body.extend_from_slice(data);

    if let Some(password) = password {
        let mut salt = [0; SALT_LEN];
        let mut nonce = [0; NONCE_LEN];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|_| Error::RandomnessUnavailable)?;
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::RandomnessUnavailable)?;
        packet.extend_from_slice(&salt);
        packet.extend_from_slice(&nonce);
        let key = key(password, &salt)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &body,
                    aad: &packet,
                },
            )
            .map_err(|_| Error::EncryptionFailed)?;
        packet.extend_from_slice(&ciphertext);
    } else {
        packet.extend_from_slice(&body);
        let checksum = Sha256::digest(&packet[..]);
        packet.extend_from_slice(&checksum);
    }
    pixels::write(image, &packet)
}

/// Validate the format and all lengths without reading or decrypting the body.
pub fn inspect(image: &RgbaImage) -> Result<PayloadInfo, Error> {
    if pixels::capacity(image) < HEADER_LEN {
        return Err(Error::InvalidFormat("image is too small for a header"));
    }
    let header = pixels::read(image, 0, HEADER_LEN)?;
    if &header[..8] != MAGIC {
        return Err(Error::InvalidFormat(
            "no v1 payload found (legacy format is unsupported)",
        ));
    }
    if header[8] != VERSION {
        return Err(Error::UnsupportedVersion(header[8]));
    }
    let encrypted = match header[9] {
        0 => false,
        1 => true,
        _ => return Err(Error::InvalidFormat("unknown flags")),
    };
    let filename_bytes = u16::from_be_bytes([header[10], header[11]]) as usize;
    if !(1..=MAX_FILENAME_LEN).contains(&filename_bytes) {
        return Err(Error::InvalidFilename);
    }
    let data_bytes = u64::from_be_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| Error::InvalidFormat("truncated length"))?,
    );
    let data_bytes = usize::try_from(data_bytes)
        .map_err(|_| Error::InvalidFormat("payload length is too large"))?;
    let total = overhead(encrypted)
        .checked_add(filename_bytes)
        .and_then(|length| length.checked_add(data_bytes))
        .ok_or(Error::InvalidFormat(
            "payload lengths overflow the supported size",
        ))?;
    if total > pixels::capacity(image) {
        return Err(Error::InvalidFormat("payload extends beyond the image"));
    }
    Ok(PayloadInfo {
        encrypted,
        filename_bytes,
        data_bytes,
    })
}

/// Decode a validated payload. No files are created by the library.
pub fn decode(image: &RgbaImage, password: Option<&[u8]>) -> Result<FileData, Error> {
    let info = inspect(image)?;
    let total = overhead(info.encrypted) + info.filename_bytes + info.data_bytes;
    let packet = Zeroizing::new(pixels::read(image, 0, total)?);
    let body = if info.encrypted {
        let password = password.ok_or(Error::PasswordRequired)?;
        let salt = &packet[HEADER_LEN..HEADER_LEN + SALT_LEN];
        let prefix_len = HEADER_LEN + SALT_LEN + NONCE_LEN;
        let nonce = &packet[HEADER_LEN + SALT_LEN..prefix_len];
        let key = key(password, salt)?;
        let cipher = XChaCha20Poly1305::new((&*key).into());
        Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(nonce),
                    Payload {
                        msg: &packet[prefix_len..],
                        aad: &packet[..prefix_len],
                    },
                )
                .map_err(|_| Error::AuthenticationFailed)?,
        )
    } else {
        if password.is_some() {
            return Err(Error::UnexpectedPassword);
        }
        let checksum_offset = total - CHECKSUM_LEN;
        let checksum = Sha256::digest(&packet[..checksum_offset]);
        if checksum[..] != packet[checksum_offset..] {
            return Err(Error::IntegrityCheckFailed);
        }
        Zeroizing::new(packet[HEADER_LEN..checksum_offset].to_vec())
    };
    let name =
        std::str::from_utf8(&body[..info.filename_bytes]).map_err(|_| Error::InvalidFilename)?;
    validate_filename(name)?;
    Ok(FileData {
        name: name.to_owned(),
        data: body[info.filename_bytes..].to_vec(),
    })
}
