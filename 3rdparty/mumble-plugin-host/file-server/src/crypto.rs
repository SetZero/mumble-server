//! Encryption-at-rest for password-protected files.
//!
//! A password-protected file's bytes are encrypted with a key **derived from
//! the uploader's password** (Argon2id over a per-file random salt), so the
//! server stores only ciphertext: without the password the content cannot be
//! recovered - not by the server, not by an admin.  A forgotten password makes
//! the file permanently unreadable, by design.
//!
//! The cipher is XChaCha20-Poly1305 in the audited **STREAM** construction
//! ([`EncryptorBE32`]/[`DecryptorBE32`]): the plaintext is split into fixed
//! [`CHUNK_SIZE`] chunks, each sealed with a per-chunk nonce derived from a
//! random per-file prefix plus a big-endian counter, and the final chunk is
//! tagged distinctly so truncation/reordering is detected.  This keeps memory
//! bounded to one chunk regardless of file size.

use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use argon2::Argon2;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::XChaCha20Poly1305;
use rand::RngCore;
use zeroize::Zeroizing;

/// Length of the per-file Argon2id key-derivation salt (bytes).
pub const ENC_SALT_BYTES: usize = 32;

/// Length of the STREAM nonce prefix stored per file.  XChaCha20-Poly1305 has a
/// 24-byte nonce; the BE32 STREAM construction consumes the last 5 bytes for
/// its counter + last-block marker, leaving a 19-byte random prefix.
pub const ENC_NONCE_PREFIX_BYTES: usize = 19;

/// Plaintext chunk size for streaming AEAD.
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Poly1305 authentication tag size appended to every ciphertext chunk.
pub const TAG_BYTES: usize = 16;

/// Errors raised by the file-encryption layer.  Variants are intentionally
/// coarse so failures never leak whether the password was wrong vs. the data
/// was corrupt.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Argon2id key derivation failed.
    #[error("key derivation failed")]
    KeyDerivation,
    /// Reading/writing a blob failed.
    #[error("crypto i/o error")]
    Io,
    /// Sealing a chunk failed.
    #[error("encryption failed")]
    Encrypt,
    /// Opening a chunk failed (wrong password or corrupt/tampered data).
    #[error("decryption failed")]
    Decrypt,
}

/// Generate a fresh random key-derivation salt.
#[must_use]
pub fn generate_enc_salt() -> [u8; ENC_SALT_BYTES] {
    let mut salt = [0u8; ENC_SALT_BYTES];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

/// Generate a fresh random STREAM nonce prefix.
#[must_use]
pub fn generate_nonce_prefix() -> [u8; ENC_NONCE_PREFIX_BYTES] {
    let mut prefix = [0u8; ENC_NONCE_PREFIX_BYTES];
    rand::thread_rng().fill_bytes(&mut prefix);
    prefix
}

/// Derive the 32-byte file key from `password` and the per-file `salt` using
/// Argon2id.  The returned key zeroizes itself on drop.
pub fn derive_file_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, key.as_mut_slice())
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(key)
}

/// Read up to `cap` bytes into a fresh buffer, stopping only at EOF.  A returned
/// length below `cap` therefore signals end-of-input.
fn read_up_to(reader: &mut impl Read, cap: usize) -> Result<Vec<u8>, CryptoError> {
    let mut buf = vec![0u8; cap];
    let mut filled = 0;
    while filled < cap {
        let n = reader
            .read(&mut buf[filled..])
            .map_err(|_| CryptoError::Io)?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    buf.truncate(filled);
    Ok(buf)
}

/// Encrypt `src_plain` into `dst_cipher` with the given key + nonce prefix.
/// The plaintext is chunked; the on-disk file is `[chunk0+tag][chunk1+tag]...`
/// with the final chunk sealed via `encrypt_last`.
pub fn encrypt_file(
    src_plain: &Path,
    dst_cipher: &Path,
    key: &[u8; 32],
    nonce_prefix: &[u8; ENC_NONCE_PREFIX_BYTES],
) -> Result<(), CryptoError> {
    let key_ga = GenericArray::from_slice(key);
    let nonce_ga = GenericArray::from_slice(nonce_prefix);
    let mut enc = Some(EncryptorBE32::<XChaCha20Poly1305>::new(key_ga, nonce_ga));

    let mut reader = BufReader::new(std::fs::File::open(src_plain).map_err(|_| CryptoError::Io)?);
    let mut writer =
        BufWriter::new(std::fs::File::create(dst_cipher).map_err(|_| CryptoError::Io)?);

    // One-chunk lookahead so the final chunk (even at an exact CHUNK_SIZE
    // boundary, or an empty file) is sealed with `encrypt_last`.
    let mut current = read_up_to(&mut reader, CHUNK_SIZE)?;
    loop {
        let next = read_up_to(&mut reader, CHUNK_SIZE)?;
        if next.is_empty() {
            let sealed = enc
                .take()
                .ok_or(CryptoError::Encrypt)?
                .encrypt_last(current.as_slice())
                .map_err(|_| CryptoError::Encrypt)?;
            writer.write_all(&sealed).map_err(|_| CryptoError::Io)?;
            break;
        }
        let sealed = enc
            .as_mut()
            .ok_or(CryptoError::Encrypt)?
            .encrypt_next(current.as_slice())
            .map_err(|_| CryptoError::Encrypt)?;
        writer.write_all(&sealed).map_err(|_| CryptoError::Io)?;
        current = next;
    }
    writer.flush().map_err(|_| CryptoError::Io)?;
    Ok(())
}

/// Decrypt `src_cipher` chunk by chunk, invoking `on_chunk` with each plaintext
/// chunk in order.  Memory use is bounded to ~two chunks.  Any tag failure
/// (wrong password, tampering, truncation) aborts with [`CryptoError::Decrypt`].
pub fn decrypt_file(
    src_cipher: &Path,
    key: &[u8; 32],
    nonce_prefix: &[u8; ENC_NONCE_PREFIX_BYTES],
    mut on_chunk: impl FnMut(Vec<u8>) -> Result<(), CryptoError>,
) -> Result<(), CryptoError> {
    let key_ga = GenericArray::from_slice(key);
    let nonce_ga = GenericArray::from_slice(nonce_prefix);
    let mut dec = Some(DecryptorBE32::<XChaCha20Poly1305>::new(key_ga, nonce_ga));

    let mut reader = BufReader::new(std::fs::File::open(src_cipher).map_err(|_| CryptoError::Io)?);
    let cipher_chunk = CHUNK_SIZE + TAG_BYTES;

    let mut current = read_up_to(&mut reader, cipher_chunk)?;
    if current.is_empty() {
        return Err(CryptoError::Decrypt);
    }
    loop {
        let next = read_up_to(&mut reader, cipher_chunk)?;
        if next.is_empty() {
            let opened = dec
                .take()
                .ok_or(CryptoError::Decrypt)?
                .decrypt_last(current.as_slice())
                .map_err(|_| CryptoError::Decrypt)?;
            on_chunk(opened)?;
            break;
        }
        let opened = dec
            .as_mut()
            .ok_or(CryptoError::Decrypt)?
            .decrypt_next(current.as_slice())
            .map_err(|_| CryptoError::Decrypt)?;
        on_chunk(opened)?;
        current = next;
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "tests panic on failure"
)]
mod tests {
    use super::*;

    fn roundtrip(plaintext: &[u8]) -> Vec<u8> {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        let cipher = dir.path().join("cipher");
        std::fs::write(&plain, plaintext).unwrap();

        let key = derive_file_key("hunter2", &[7u8; ENC_SALT_BYTES]).unwrap();
        let prefix = generate_nonce_prefix();
        encrypt_file(&plain, &cipher, &key, &prefix).unwrap();

        // Ciphertext must not equal plaintext (and be larger by >= one tag).
        let ct = std::fs::read(&cipher).unwrap();
        assert_ne!(ct, plaintext);
        assert!(ct.len() >= plaintext.len() + TAG_BYTES);

        let mut out = Vec::new();
        decrypt_file(&cipher, &key, &prefix, |chunk| {
            out.extend_from_slice(&chunk);
            Ok(())
        })
        .unwrap();
        out
    }

    #[test]
    fn roundtrip_small() {
        let pt = b"the eagle lands at midnight";
        assert_eq!(roundtrip(pt), pt);
    }

    #[test]
    fn roundtrip_empty() {
        assert_eq!(roundtrip(b""), b"");
    }

    #[test]
    fn roundtrip_multi_chunk() {
        // > 2 full chunks plus a partial tail.
        let pt: Vec<u8> = (0..CHUNK_SIZE * 2 + 1234)
            .map(|i| (i % 251) as u8)
            .collect();
        assert_eq!(roundtrip(&pt), pt);
    }

    #[test]
    fn roundtrip_exact_chunk_multiple() {
        let pt: Vec<u8> = (0..CHUNK_SIZE * 2).map(|i| (i % 97) as u8).collect();
        assert_eq!(roundtrip(&pt), pt);
    }

    #[test]
    fn wrong_password_fails() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        let cipher = dir.path().join("cipher");
        std::fs::write(&plain, b"secret payload").unwrap();
        let salt = [9u8; ENC_SALT_BYTES];
        let prefix = generate_nonce_prefix();
        let key = derive_file_key("correct", &salt).unwrap();
        encrypt_file(&plain, &cipher, &key, &prefix).unwrap();

        let wrong = derive_file_key("wrong", &salt).unwrap();
        let err = decrypt_file(&cipher, &wrong, &prefix, |_| Ok(())).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain");
        let cipher = dir.path().join("cipher");
        std::fs::write(&plain, b"authenticated bytes").unwrap();
        let key = derive_file_key("pw", &[3u8; ENC_SALT_BYTES]).unwrap();
        let prefix = generate_nonce_prefix();
        encrypt_file(&plain, &cipher, &key, &prefix).unwrap();

        let mut ct = std::fs::read(&cipher).unwrap();
        ct[0] ^= 0x01;
        std::fs::write(&cipher, &ct).unwrap();
        let err = decrypt_file(&cipher, &key, &prefix, |_| Ok(())).unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn derive_is_deterministic_and_salt_sensitive() {
        let a = derive_file_key("pw", &[1u8; ENC_SALT_BYTES]).unwrap();
        let b = derive_file_key("pw", &[1u8; ENC_SALT_BYTES]).unwrap();
        let c = derive_file_key("pw", &[2u8; ENC_SALT_BYTES]).unwrap();
        assert_eq!(a.as_slice(), b.as_slice());
        assert_ne!(a.as_slice(), c.as_slice());
    }
}
