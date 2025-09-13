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
const AUTH_TAG_SIZE: usize = 16;
const CIPHER_TEXT_BLOCK_SIZE: usize = ENCRYPTION_BUFFER_SIZE + AUTH_TAG_SIZE;
const BUFFER_SIZE_INDICATOR_SIZE: usize = 4;
const IV_LENGTH: usize = 12;
const READER_BUFFER_SIZE: usize = ENCRYPTION_BUFFER_SIZE;
const WRITER_BUFFER_SIZE: usize =
    IV_LENGTH + BUFFER_SIZE_INDICATOR_SIZE + ENCRYPTION_BUFFER_SIZE + AUTH_TAG_SIZE;

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

/// A wrapper around `BufReader` that provides buffered reading for an underlying reader.
/// The buffer size is set to match the encryption mechanism.
///
/// # Type Parameters
/// - `R`: The type of the inner reader. Must implement `std::io::Read`.
pub struct EncryptionReader<R> {
    reader: BufReader<R>,
}

impl<R: Read> EncryptionReader<R> {
    /// Creates a new `EncryptionReader` from any type that implements `Read`.
    pub fn from_reader(source: R) -> EncryptionReader<R> {
        EncryptionReader {
            reader: BufReader::with_capacity(READER_BUFFER_SIZE, source),
        }
    }

    /// Consumes the `EncryptionReader` and returns the inner `BufReader`.
    pub fn inner(&mut self) -> &mut BufReader<R> {
        &mut self.reader
    }
}

/// A wrapper around `BufWriter` that provides buffered writing for an underlying writer.
/// The buffer size is set to match the decryption mechanism.
///
/// # Type Parameters
/// - `W`: The type of the inner writer. Must implement `std::io::Write`.
pub struct EncryptionWriter<W: Write> {
    writer: BufWriter<W>,
}

impl<W: Write> EncryptionWriter<W> {
    /// Creates a new `EncryptionWriter` from any type that implements `Write`.
    pub fn from_writer(destination: W) -> EncryptionWriter<W> {
        EncryptionWriter {
            writer: BufWriter::with_capacity(WRITER_BUFFER_SIZE, destination),
        }
    }

    /// Flushes the internal writer, ensuring all buffered data is written.
    ///
    /// Returns any I/O error encountered.
    pub fn flush(&mut self) -> Result<(), std::io::Error> {
        self.writer.flush()
    }

    /// Consumes the `EncryptionWriter` and returns the inner `BufWriter`.
    pub fn inner(&mut self) -> &mut BufWriter<W> {
        &mut self.writer
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
pub fn encrypt_from_stream<R: Read + Seek, W: Write>(
    key: &Key,
    hint: Option<String>,
    reader: &mut EncryptionReader<R>,
    writer: &mut EncryptionWriter<W>,
) -> Result<(), Error> {
    let writer = writer.inner();
    let reader = reader.inner();
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
pub fn decrypt_from_stream<R: Read + Seek, W: Write>(
    key: &Key,
    reader: &mut EncryptionReader<R>,
    writer: &mut EncryptionWriter<W>,
) -> Result<(), Error> {
    let reader = reader.inner();
    let writer = writer.inner();
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
pub fn hint<R: Read>(reader: &mut std::io::BufReader<R>) -> Option<String> {
    let mut hint_length_buf = [0u8; 1];
    reader.read_exact(&mut hint_length_buf).ok()?;
    let hint_length = hint_length_buf[0] as usize;

    if hint_length == 0 {
        return None;
    }

    let mut hint_buf = vec![0u8; hint_length];
    if reader.read_exact(&mut hint_buf).is_err() {
        return None;
    }

    str::from_utf8(&hint_buf).ok().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use rand::RngCore;

    use super::*;

    fn create_cusor(data: Vec<u8>) -> std::io::Cursor<Vec<u8>> {
        std::io::Cursor::new(data)
    }

    #[test]
    fn none_if_no_hint_present() {
        let file = vec![0u8, 65u8, 65u8, 65u8, 65u8];
        let cursor = create_cusor(file);
        let mut reader = std::io::BufReader::new(cursor);

        let maybe_hint = hint(&mut reader);

        assert_eq!(None, maybe_hint);
    }

    #[test]
    fn some_if_hint_present() {
        let file = vec![3u8, 65u8, 65u8, 65u8, 65u8];
        let cursor = create_cusor(file);
        let mut reader = std::io::BufReader::new(cursor);

        let maybe_hint = hint(&mut reader);

        assert_eq!(Some("AAA".to_string()), maybe_hint);
    }

    #[test]
    fn decrypt_encrypted_data_is_original_data() {
        let key = Key::from_str("password");

        // Generate 1 MB of random plaintext.
        // Encrypt it, then decrypt it and check that the two plain text matches.
        let mut initial_plain_text = vec![0u8; 1024 * 1024];
        rand::rng().fill_bytes(&mut initial_plain_text);

        let cursor = create_cusor(initial_plain_text.clone());
        let reader = std::io::BufReader::new(cursor);
        let mut reader = EncryptionReader::from_reader(reader);

        let mut writer_buf = Vec::new();
        {
            let writer = std::io::BufWriter::new(&mut writer_buf);
            let mut writer = EncryptionWriter::from_writer(writer);

            encrypt_from_stream(&key, Some("Hi".to_string()), &mut reader, &mut writer).unwrap();
        }

        let cipher_text = writer_buf;
        let mut reader = EncryptionReader::from_reader(create_cusor(cipher_text.clone()));

        let mut decrypted_plain_text = Vec::new();
        {
            let writer = std::io::BufWriter::new(&mut decrypted_plain_text);
            let mut writer = EncryptionWriter::from_writer(writer);

            decrypt_from_stream(&key, &mut reader, &mut writer).unwrap();
        }

        assert_ne!(initial_plain_text, cipher_text);
        assert_eq!(initial_plain_text, decrypted_plain_text);
    }
}
