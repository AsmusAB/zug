use hex::FromHex;

const KEY_LENGTH: usize = 32;

/// Represents a 256-bit (32-byte) key used for AES encryption and decryption.
///
/// This key is derived from a UTF-8 string using a SHA-256 hash.
/// Note: The security of this key is limited by the entropy of the input string.
#[derive(Debug)]
pub struct Key {
    hash: [u8; KEY_LENGTH],
}

impl Key {
    /// Creates a new `Key` by computing the SHA-256 hash of the given string.
    ///
    /// # Arguments
    ///
    /// * `str` - The input string to hash.
    pub fn from_str(str: &str) -> Key {
        let digest = sha256::digest(str);
        let hash = <[u8; KEY_LENGTH]>::from_hex(digest).expect("Invalid hex or wrong length");
        Key { hash }
    }

    /// Returns the raw 32-byte key.
    pub fn bytes(&self) -> [u8; KEY_LENGTH] {
        self.hash
    }
}
