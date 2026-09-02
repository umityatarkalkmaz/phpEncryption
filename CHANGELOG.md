# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-09-02

### Security

- **The cipher was used without an IV.** `openssl_encrypt()` was called with no
  fourth argument, so AES-256-CBC ran with an all-zero IV: the same plaintext
  always produced the same ciphertext. Anyone watching URLs or a database column
  could tell equal values apart from different ones, match a known plaintext to
  its ciphertext, and build a lookup table. Every message now carries a random
  24-byte nonce.
- **Ciphertexts were unauthenticated.** CBC without a MAC is malleable: an
  attacker could flip bits in a URL token and the result would still decrypt,
  into a value nobody chose. The cipher is now XChaCha20-Poly1305, which rejects
  any modified ciphertext.
- **The key was a passphrase.** A string such as `'MY-SECRET-KEY'` was handed
  straight to OpenSSL as raw key material and zero-padded to 32 bytes, leaving
  most of the key empty. The constructor now requires a base64-encoded 32-byte
  key and refuses anything else; `generateKey()` produces one.
- The key is marked `#[SensitiveParameter]` and hidden from `var_dump()`, so it
  does not appear in stack traces or debug output.

### Fixed

- `encryptUrl()` and `encryptDb()` declared `: string` but returned whatever
  `openssl_encrypt()` gave them, so a failure raised a `TypeError` instead of
  being reported.
- Decryption returned `false` both for a wrong key and for corrupt input,
  without distinguishing either from a legitimately decrypted `''`. It now
  returns `null` on any failure, and `''` only for an empty plaintext.

### Changed

- **BREAKING:** `encryptDb()`/`decryptDb()` are now `encrypt()`/`decrypt()`, and
  `encryptUrl()`/`decryptUrl()` are now `encryptForUrl()`/`decryptFromUrl()`.
- **BREAKING:** the decrypt methods return `?string` instead of `false|string`.
- **BREAKING:** the constructor takes a generated key, not a passphrase.
- **BREAKING:** the ciphertext format changed completely. **Ciphertexts written
  by 1.x cannot be read by 2.x.** Migrate by decrypting with the old class and
  re-encrypting with the new one before upgrading; there is no in-place path,
  because the old format has no way to tell a valid ciphertext from a forged one.
- **BREAKING:** `src/encryption.php` is now `src/Encryption.php`, so PSR-4
  autoloading works on a case-sensitive filesystem.
- **BREAKING:** the class is `final`.
- The URL encoding is now standard base64url (`-`, `_`, no padding) instead of
  mapping `=` to `,`.

### Added

- `generateKey()`.
- `composer.json` with PSR-4 autoloading, published as
  `umityatarkalkmaz/encryption`.
- PHPUnit test suite and PHPStan (level max) analysis.
- GitHub Actions CI across PHP 8.2, 8.3, 8.4 and 8.5.

## [1.0.0]

- Initial release.
