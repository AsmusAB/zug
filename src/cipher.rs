use std::{
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    vec,
};

use aes_gcm_siv::{
    Aes256GcmSiv,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};

use crate::key::Key;

const ENCRYPTION_BUFFER_SIZE: usize = 1024 * 64;
const CIPHER_TEXT_BLOCK_SIZE: usize = ENCRYPTION_BUFFER_SIZE + 16;
const BUFFER_SIZE_INDICATOR_SIZE: usize = 4;
const IV_LENGTH: usize = 12;

#[derive(Debug)]
/// Represents possible errors that can occur when encrypting a file.
pub enum EncryptionError {
    /// An error occured when writing to the output stream.
    WriteToStreamError,
    AesError,
}

impl From<std::io::Error> for EncryptionError {
    fn from(_: std::io::Error) -> Self {
        EncryptionError::WriteToStreamError
    }
}

impl From<aes_gcm_siv::Error> for EncryptionError {
    fn from(_: aes_gcm_siv::Error) -> Self {
        EncryptionError::AesError
    }
}

/// Encrypts the given file contents using AES-GCM with a random IV.
/// Prepends the encoded hint and IV to the output buffer.
///
/// The final format is:
/// `[hint_len (1 byte)][hint][iv (12 bytes)][ciphertext]`
///
/// # Arguments
///
/// * `key` - The AES key to use for encryption.
/// * `context` - The encryption context containing file data and optional hint.
///
/// # Returns
///
/// A `Vec<u8>` containing the formatted encrypted payload.
pub fn encrypt_from_stream(
    key: &Key,
    hint: Option<String>,
    reader: &mut BufReader<std::fs::File>,
    writer: &mut BufWriter<std::fs::File>,
) -> Result<(), EncryptionError> {
    let aes_key: &aes_gcm_siv::Key<Aes256GcmSiv> = &key.bytes().into();
    let cipher = Aes256GcmSiv::new(aes_key);

    let hint_bytes = hint.unwrap_or_default().into_bytes();
    writer.write_all(&[(hint_bytes.len() as u8)])?;

    writer.write_all(&hint_bytes)?;

    let mut buf = [0u8; ENCRYPTION_BUFFER_SIZE];

    loop {
        let nonce = Aes256GcmSiv::generate_nonce(&mut OsRng);

        let bytes_read = reader.read(&mut buf).unwrap();

        let cipher_text = cipher.encrypt(&nonce, &buf[..bytes_read])?;

        writer.write_all(&nonce)?;
        writer.write_all(&(cipher_text.len() as u32).to_le_bytes())?;
        writer.write_all(&cipher_text)?;

        if bytes_read < ENCRYPTION_BUFFER_SIZE {
            break;
        }
    }

    Ok(())
}

/// Decrypts the encrypted contents stored in the `DecryptionContext`.
///
/// Uses AES-GCM with the IV extracted from the context. Assumes the file contents
/// are in-place decryptable (i.e., the ciphertext buffer will become the plaintext).
///
/// # Arguments
///
/// * `key` - The AES key to use for decryption.
/// * `context` - The decryption context containing the encrypted data and IV.
///
/// # Returns
///
/// `Some(plaintext)` on success, or `None` if decryption fails (e.g., wrong key or authentication error).
pub fn decrypt_from_stream(
    key: &Key,
    reader: &mut BufReader<std::fs::File>,
    writer: &mut BufWriter<std::fs::File>,
) {
    let aes_key: &aes_gcm_siv::Key<Aes256GcmSiv> = &key.bytes().into();
    let cipher = Aes256GcmSiv::new(aes_key);

    let mut hint_length = [0u8; 1];
    reader
        .read_exact(&mut hint_length)
        .expect("Could not read decryption stream.");

    reader
        .seek(SeekFrom::Current(hint_length[0] as i64))
        .expect("Stream ended before reading full hint.");

    // Nonce | Cipher Text Length | Max Cipher Length + Tag
    let mut buf = [0u8; IV_LENGTH + BUFFER_SIZE_INDICATOR_SIZE + CIPHER_TEXT_BLOCK_SIZE];

    loop {
        let bytes_read = reader.read(&mut buf).unwrap();
        let nonce = &buf[..IV_LENGTH];
        let cipher_text_length = u32::from_le_bytes(
            buf[IV_LENGTH..IV_LENGTH + 4]
                .try_into()
                .expect("Could not read block length from decryption stream."),
        ) as usize;
        let cipher_text = &buf[IV_LENGTH + 4..IV_LENGTH + 4 + cipher_text_length];

        let plain_text = cipher
            .decrypt(nonce.into(), cipher_text)
            .expect("Internal AES decryption error.");

        writer
            .write_all(&plain_text)
            .expect("Could not write to output stream");

        if bytes_read < IV_LENGTH + BUFFER_SIZE_INDICATOR_SIZE + CIPHER_TEXT_BLOCK_SIZE {
            break;
        }
    }
}

/// Extracts the hint string from the beginning of an encrypted file, if present.
///
/// Assumes the file format starts with:
/// `[hint_len (1 byte)][hint (hint_len bytes)][iv (12 bytes)][ciphertext]`
///
/// # Arguments
///
/// * `path` - A reference to the file path to read the hint from.
///
/// # Returns
///
/// * `Some(String)` containing the UTF-8 decoded hint if present and valid.
/// * `None` if the file can't be opened, the hint length is zero, the hint can't be read,
///   or the hint is not valid UTF-8.
pub fn hint(path: &std::path::Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;

    let mut hint_length_buf = [0u8; 1];
    file.read_exact(&mut hint_length_buf).ok()?;
    let hint_length = hint_length_buf[0] as usize;

    if hint_length == 0 {
        return None;
    }

    let mut hint_buf = vec![0u8; hint_length];
    if file.read_exact(&mut hint_buf).is_err() {
        return None;
    }

    str::from_utf8(&hint_buf).ok().map(|s| s.to_string())
}
