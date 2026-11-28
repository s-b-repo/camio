//! Passphrase-based authenticated encryption for workspace export (plan §F04
//! "encrypted import/export", "protected session storage").
//!
//! A captured workspace holds request/response bodies that can contain
//! credentials, tokens, and PII. [`seal`] turns a plaintext blob (typically a
//! consistent DB backup) into a self-describing encrypted container that is safe
//! to move off the machine; [`open`] reverses it given the passphrase. The
//! cryptography is **not hand-rolled**: the key comes from PBKDF2-HMAC-SHA256
//! over the passphrase and a random salt, and the payload is sealed with
//! XChaCha20-Poly1305 (a 24-byte random nonce, so nonce reuse is not a concern)
//! — both from the audited RustCrypto crates.
//!
//! Container layout (all integers big-endian):
//! `MAGIC(8) | VERSION(1) | iters(4) | salt(16) | nonce(24) | ciphertext+tag`.
//! The KDF iteration count travels in the header so a file sealed with one count
//! still opens after the default changes.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use sha2::Sha256;

const MAGIC: &[u8; 8] = b"CAMIOENC";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 8 + 1 + 4 + SALT_LEN + NONCE_LEN;

/// Default PBKDF2-HMAC-SHA256 iteration count (OWASP guidance for SHA-256). A
/// one-shot cost at export/import time, not a hot path.
pub const DEFAULT_PBKDF2_ITERS: u32 = 600_000;

/// A sane upper bound on the iteration count read from an untrusted header, so a
/// corrupt/hostile file cannot wedge the process in the KDF.
const MAX_PBKDF2_ITERS: u32 = 50_000_000;

/// What can go wrong sealing or opening a container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretboxError {
    /// The OS RNG would not produce a salt/nonce.
    Random,
    /// Authenticated encryption failed (should not happen for valid inputs).
    Encrypt,
    /// Decryption/authentication failed: wrong passphrase or tampered data.
    Decrypt,
    /// The container is too short, lacks the magic, or has an out-of-range
    /// iteration count.
    Format,
    /// The container's version is one this build does not understand.
    Version(u8),
}

impl std::fmt::Display for SecretboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretboxError::Random => write!(f, "no secure random bytes available"),
            SecretboxError::Encrypt => write!(f, "encryption failed"),
            SecretboxError::Decrypt => {
                write!(f, "could not decrypt: wrong passphrase or the data was altered")
            }
            SecretboxError::Format => write!(f, "not a Camio encrypted container"),
            SecretboxError::Version(v) => write!(f, "unsupported container version {v}"),
        }
    }
}

impl std::error::Error for SecretboxError {}

/// Derive the content key from the passphrase and salt.
fn derive_key(passphrase: &str, salt: &[u8], iters: u32) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, iters, &mut key);
    key
}

/// Encrypt `plaintext` under `passphrase`, using `iters` PBKDF2 rounds (pass
/// [`DEFAULT_PBKDF2_ITERS`] in production). Returns the full container bytes.
pub fn seal(plaintext: &[u8], passphrase: &str, iters: u32) -> Result<Vec<u8>, SecretboxError> {
    let iters = iters.clamp(1, MAX_PBKDF2_ITERS);
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| SecretboxError::Random)?;
    getrandom::fill(&mut nonce).map_err(|_| SecretboxError::Random)?;

    let key = derive_key(passphrase, &salt, iters);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext)
        .map_err(|_| SecretboxError::Encrypt)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&iters.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a container produced by [`seal`], returning the plaintext. Fails with
/// [`SecretboxError::Decrypt`] on a wrong passphrase or any tampering (the AEAD
/// tag authenticates the whole payload).
pub fn open(container: &[u8], passphrase: &str) -> Result<Vec<u8>, SecretboxError> {
    if container.len() < HEADER_LEN + TAG_LEN {
        return Err(SecretboxError::Format);
    }
    if &container[0..8] != MAGIC {
        return Err(SecretboxError::Format);
    }
    let version = container[8];
    if version != VERSION {
        return Err(SecretboxError::Version(version));
    }
    let iters = u32::from_be_bytes([container[9], container[10], container[11], container[12]]);
    if iters == 0 || iters > MAX_PBKDF2_ITERS {
        return Err(SecretboxError::Format);
    }
    let salt = &container[13..13 + SALT_LEN];
    let nonce = &container[13 + SALT_LEN..13 + SALT_LEN + NONCE_LEN];
    let ciphertext = &container[HEADER_LEN..];

    let key = derive_key(passphrase, salt, iters);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| SecretboxError::Decrypt)
}

/// Whether `data` looks like a Camio encrypted container (cheap magic check).
pub fn is_container(data: &[u8]) -> bool {
    data.len() >= 8 && &data[0..8] == MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;

    // Small iteration count keeps the KDF fast in tests; the count is stored in
    // the header, so `open` uses whatever `seal` used.
    const T_ITERS: u32 = 64;

    #[test]
    fn round_trips_plaintext() {
        let msg = b"captured bodies with a secret: Bearer abc123";
        let sealed = seal(msg, "correct horse", T_ITERS).unwrap();
        assert!(is_container(&sealed));
        assert_ne!(&sealed[HEADER_LEN..], &msg[..], "payload must be encrypted");
        let opened = open(&sealed, "correct horse").unwrap();
        assert_eq!(opened, msg);
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let sealed = seal(b"secret", "right", T_ITERS).unwrap();
        assert_eq!(open(&sealed, "wrong"), Err(SecretboxError::Decrypt));
    }

    #[test]
    fn tampering_is_detected() {
        let mut sealed = seal(b"secret data", "pw", T_ITERS).unwrap();
        // Flip a byte in the ciphertext body; the AEAD tag must reject it.
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        assert_eq!(open(&sealed, "pw"), Err(SecretboxError::Decrypt));
    }

    #[test]
    fn two_seals_differ_by_salt_and_nonce() {
        // Randomized salt+nonce → identical plaintext seals to distinct bytes.
        let a = seal(b"same", "pw", T_ITERS).unwrap();
        let b = seal(b"same", "pw", T_ITERS).unwrap();
        assert_ne!(a, b);
        assert_eq!(open(&a, "pw").unwrap(), open(&b, "pw").unwrap());
    }

    #[test]
    fn rejects_foreign_or_short_input() {
        assert_eq!(open(b"too short", "pw"), Err(SecretboxError::Format));
        assert_eq!(open(&[0u8; 80], "pw"), Err(SecretboxError::Format));
        assert!(!is_container(b"PK\x03\x04 zip"));
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let sealed = seal(b"", "pw", T_ITERS).unwrap();
        assert_eq!(open(&sealed, "pw").unwrap(), b"");
    }
}
