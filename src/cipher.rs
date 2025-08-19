use std::{
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    vec,
};

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{Aead, AeadCore, AeadMutInPlace, KeyInit, OsRng},
};

use crate::key::Key;

const ENCRYPTION_BUFFER_SIZE: usize = 1024 * 64;
const CIPHER_TEXT_BLOCK_SIZE: usize = ENCRYPTION_BUFFER_SIZE + 16;
const BUFFER_SIZE_INDICATOR_SIZE: usize = 4;
const IV_LENGTH: usize = 12;

/// Represents the encryption context, containing the file data to be encrypted
/// and an optional hint.
#[derive(Debug)]
pub struct EncryptionContext {
    file_contents: Vec<u8>,
    hint: Option<String>,
}

impl EncryptionContext {
    /// Constructs a new `EncryptionContext`.
    ///
    /// Returns `None` if the provided hint is longer than 255 bytes, since
    /// the hint length is stored in a single byte during encryption.
    ///
    /// # Arguments
    ///
    /// * `file_contents` - The file contents to be encrypted.
    /// * `hint` - An optional hint string (must be <= 255 bytes if present).
    pub fn new(file_contents: Vec<u8>, hint: Option<String>) -> Option<EncryptionContext> {
        if let Some(ref hint) = hint
            && hint.len() > 255
        {
            return None;
        }

        Some(EncryptionContext {
            file_contents,
            hint,
        })
    }
}

#[derive(Debug)]
/// Represents possible errors that can occur when constructing a `DecryptionContext`.
pub enum DecryptionContextError {
    /// The file is too short to contain a valid hint and IV.
    FileTooShort,
    /// The hint length field is invalid given the total file size.
    HintLengthMismatch,
    /// The IV could not be extracted or parsed correctly.
    MissingIV,
}

#[derive(Debug)]
/// Holds the context necessary for decrypting an encrypted file.
pub struct DecryptionContext {
    file_contents: Vec<u8>,
    iv: [u8; IV_LENGTH],
}

impl DecryptionContext {
    /// Constructs a `DecryptionContext` from the provided encrypted file data.
    ///
    /// Expects the data format to be:
    /// `[hint_len (1 byte)][hint (hint_len bytes)][iv (12 bytes)][ciphertext]`
    ///
    /// Returns an error if the input is too short or improperly formatted.
    ///
    /// # Arguments
    ///
    /// * `file_contents` - The full contents of the encrypted file.
    pub fn from_file(
        mut file_contents: Vec<u8>,
    ) -> Result<DecryptionContext, DecryptionContextError> {
        if file_contents.len() <= 13 {
            return Err(DecryptionContextError::FileTooShort);
        }

        let hint_length = file_contents[0] as usize;
        if file_contents.len() < 1 + hint_length + IV_LENGTH {
            return Err(DecryptionContextError::HintLengthMismatch);
        }

        file_contents.remove(0);
        file_contents.drain(0..hint_length);
        let iv: Vec<u8> = file_contents.drain(0..IV_LENGTH).collect();

        iv.try_into()
            .map_err(|_| DecryptionContextError::MissingIV)
            .map(|iv| DecryptionContext { file_contents, iv })
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
pub fn encrypt(key: &Key, context: EncryptionContext) -> Vec<u8> {
    let aes_key: &aes_gcm_siv::Key<Aes256GcmSiv> = &key.bytes().into();
    let cipher = Aes256GcmSiv::new(aes_key);
    let iv = Aes256GcmSiv::generate_nonce(&mut OsRng);

    let mut encrypted_bytes = cipher
        .encrypt(&iv, &context.file_contents[..])
        .expect("Internal AES encryption error.");

    let mut hint = context.hint.unwrap_or_default().into_bytes();

    let needed_bytes = 1 + hint.len() + 12 + encrypted_bytes.len();

    let mut buf: Vec<u8> = Vec::with_capacity(needed_bytes);

    buf.push(hint.len() as u8);
    buf.append(&mut hint);
    buf.append(&mut iv.as_slice().to_vec());
    buf.append(&mut encrypted_bytes);

    debug_assert_eq!(needed_bytes, buf.len());

    buf
}

pub fn encrypt_from_stream(
    key: &Key,
    hint: Option<String>,
    reader: &mut BufReader<std::fs::File>,
    writer: &mut BufWriter<std::fs::File>,
) {
    let aes_key: &aes_gcm_siv::Key<Aes256GcmSiv> = &key.bytes().into();
    let cipher = Aes256GcmSiv::new(aes_key);

    let hint_bytes = hint.unwrap_or_default().into_bytes();
    writer
        .write_all(&[(hint_bytes.len() as u8)])
        .expect("Could not write to output stream");
    writer
        .write_all(&hint_bytes)
        .expect("Could not write to output stream");

    let mut buf = [0u8; ENCRYPTION_BUFFER_SIZE];

    loop {
        let nonce = Aes256GcmSiv::generate_nonce(&mut OsRng);

        let bytes_read = reader.read(&mut buf).unwrap();

        let cipher_text = cipher
            .encrypt(&nonce, &buf[..bytes_read])
            .expect("Internal AES encryption error.");

        writer
            .write_all(&nonce)
            .expect("Could not write to output stream");

        writer
            .write_all(&(cipher_text.len() as u32).to_le_bytes())
            .expect("Could not write to output stream");

        writer
            .write_all(&cipher_text)
            .expect("Could not write to output stream");

        if bytes_read < ENCRYPTION_BUFFER_SIZE {
            break;
        }
    }
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
pub fn decrypt(key: &Key, mut context: DecryptionContext) -> Option<Vec<u8>> {
    let aes_key: &aes_gcm_siv::Key<Aes256GcmSiv> = &key.bytes().into();
    let mut cipher = Aes256GcmSiv::new(aes_key);
    let iv = Nonce::from_slice(&context.iv);

    cipher
        .decrypt_in_place(iv, b"", &mut context.file_contents)
        .ok()
        .map(|_| context.file_contents)
}

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
