# zug

**zug** is a simple Rust command-line utility for encrypting and decrypting files using AES-256-GCM-SIV encryption.

The project derives its name from the Swiss canton of *Zug*. Switzerland being one of the countries with the strongest privacy laws on earth. 🇨🇭🏔️

---

## Features

- Encrypt and decrypt files using a password-derived 256-bit key (SHA-256 hashed).
- Embed optional human-readable hints in encrypted files.
- Secure, chunked streaming encryption with AES-256-GCM-SIV.
- Authentication on every encrypted block.
---

## Usage

Encrypt a file.
```bash
zug -e <password> -h [hint] <path>
```
Decrypt a file.
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
zug -e "VerySecurePassword" -h "my hint" my-file.txt
```

---

## Internals

- Key Derivation:
  Passwords are hashed with SHA-256 to produce a 256-bit key.

- Encryption Format:
  The encrypted file is structured as follows:

      [1-byte hint length]
      [hint bytes]

      For each block:
          [12-byte random nonce]
          [4-byte ciphertext length (little endian)]
          [ciphertext (<= 64 KiB + 16-byte authentication tag)]

- Streaming:
  Files are encrypted and decrypted in 64 KiB blocks.
  Each block uses its own random nonce and authentication tag, ensuring integrity.

- Cryptography:
  Built on the aes-gcm-siv crate for AES-256-GCM-SIV encryption.

---

## License

Copyright 2025 Asmus Bartram

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
