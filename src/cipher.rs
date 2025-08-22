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
pub enum Error {
    WriteToStreamError,
    AesError,
}

impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Error::WriteToStreamError
    }
}

impl From<aes_gcm_siv::Error> for Error {
    fn from(_: aes_gcm_siv::Error) -> Self {
        Error::AesError
    }
}

/// Encrypts a file stream in chunks using AES-256-GCM-SIV with per-block nonces.
///
/// The output format is:
/// ```text
/// [hint_len (1 byte)]
/// [hint (hint_len bytes)]
/// repeat for each block:
///   [nonce (12 bytes)]
///   [ciphertext_len (4 bytes, little endian)]
///   [ciphertext (ciphertext_len bytes)]
/// ```
///
/// Each block is at most 64 KiB of plaintext + 16 bytes authentication tag.
/// A fresh random nonce is generated for each block.
///
/// # Arguments
///
/// * `key` – The AES key used for encryption.
/// * `hint` – An optional string hint to embed in the encrypted file.
/// * `reader` – Input file reader.
/// * `writer` – Output file writer.
///
/// # Returns
///
/// `Ok(())` on success, or `Error` on I/O or encryption failure.
pub fn encrypt_from_stream(
    key: &Key,
    hint: Option<String>,
    reader: &mut BufReader<std::fs::File>,
    writer: &mut BufWriter<std::fs::File>,
) -> Result<(), Error> {
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

/// Decrypts a file stream produced by [`encrypt_from_stream`].
///
/// The input format is expected to be:
/// ```text
/// [hint_len (1 byte)]
/// [hint (hint_len bytes)]
/// repeat for each block:
///   [nonce (12 bytes)]
///   [ciphertext_len (4 bytes, little endian)]
///   [ciphertext (ciphertext_len bytes)]
/// ```
///
/// Decryption is performed block-by-block, verifying the AES-GCM-SIV tag for
/// each ciphertext before writing the plaintext to the output stream.
///
/// # Arguments
///
/// * `key` – The AES key used for decryption.
/// * `reader` – Encrypted input file reader.
/// * `writer` – Decrypted output file writer.
///
/// # Returns
///
/// `Ok(())` on success, or `Error` on I/O or authentication failure.
pub fn decrypt_from_stream(
    key: &Key,
    reader: &mut BufReader<std::fs::File>,
    writer: &mut BufWriter<std::fs::File>,
) -> Result<(), Error> {
    let aes_key: &aes_gcm_siv::Key<Aes256GcmSiv> = &key.bytes().into();
    let cipher = Aes256GcmSiv::new(aes_key);

    let mut hint_length = [0u8; 1];
    reader.read_exact(&mut hint_length)?;

    reader.seek(SeekFrom::Current(hint_length[0] as i64))?;

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

        let plain_text = cipher.decrypt(nonce.into(), cipher_text)?;

        writer.write_all(&plain_text)?;

        if bytes_read < IV_LENGTH + BUFFER_SIZE_INDICATOR_SIZE + CIPHER_TEXT_BLOCK_SIZE {
            break;
        }
    }

    Ok(())
}

/// Extracts the hint string from the beginning of an encrypted file, if present.
///
/// Assumes the file format starts with:
/// `[hint_len (1 byte)][hint (hint_len bytes)]`
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
