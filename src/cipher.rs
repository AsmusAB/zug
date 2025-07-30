use std::io::Read;

use aes_gcm_siv::{
    Aes256GcmSiv, Nonce,
    aead::{Aead, AeadCore, AeadMutInPlace, KeyInit, OsRng},
};

use crate::key::Key;

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
        if let Some(ref hint) = hint {
            if hint.len() > 255 {
                return None;
            }
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
