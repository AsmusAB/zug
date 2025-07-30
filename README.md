# zug

**zug** is a simple Rust command-line utility for encrypting and decrypting files using AES-256-GCM-SIV encryption.

The project derives its name from the Swiss canton of *Zug*. Switzerland being one of the countries with the strongest privacy laws on earth. 🇨🇭🏔️

---

## Features

- Encrypt and decrypt files using a password-derived 256-bit key (SHA-256 hashed).
- Embeds optional hints in encrypted files.
- Uses AES-256-GCM-SIV for encryption.
---

## Usage

File encryption.
```bash
zug -e <password> <path> [hint]
```
File decryption.
```bash
zug -d <password> <path>
```
Display file hint.
```bash
zug -h <path>
```

- `<password>` : Password used for encryption/decryption.
- `<path>` : Path to the file to encrypt.
- `[hint]` : (OPTIONAL) Embed a hint in the encrypted file.

---

## Example

```bash
zug -e "VerySecurePassword" ./my-file.txt
```

---

## Internals

- **Key Derivation**: Uses SHA-256 to hash the password into a 256-bit key.
- **Encryption Format**:
  ```
  [1-byte hint length][hint bytes][12-byte IV][encrypted data]
  ```
- **Cryptography**: Uses the `aes-gcm_siv` crate for AES-256-GCM-SIV encryption.

---

## Future Improvements

- Support for streaming large files.

---

## License

Copyright 2025 Asmus Bartram

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
