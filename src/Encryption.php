<?php

declare(strict_types=1);

namespace UmitYatarkalkmaz;

use InvalidArgumentException;
use SensitiveParameter;
use SodiumException;

/**
 * Authenticated encryption for values you store or put in a URL.
 *
 * Uses XChaCha20-Poly1305 with a random nonce per message, so the same
 * plaintext never produces the same ciphertext twice and any modification to a
 * ciphertext is detected rather than decrypted into garbage.
 */
final class Encryption
{
    /** Distinguishes this format from whatever replaces it. */
    private const VERSION = "\x01";

    private const KEY_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
    private const NONCE_BYTES = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;

    private readonly string $key;

    /**
     * @param string $key a base64-encoded 32-byte key, as produced by generateKey()
     *
     * @throws InvalidArgumentException when the key is not a usable 32-byte key
     */
    public function __construct(#[SensitiveParameter] string $key)
    {
        $raw = base64_decode($key, true);

        if ($raw === false) {
            throw new InvalidArgumentException(
                'The key must be a base64-encoded 32-byte key; a passphrase is not a key. See Encryption::generateKey().',
            );
        }

        if (strlen($raw) !== self::KEY_BYTES) {
            throw new InvalidArgumentException(sprintf(
                'The key must decode to exactly %d bytes, got %d. A passphrase is not a key; see Encryption::generateKey().',
                self::KEY_BYTES,
                strlen($raw),
            ));
        }

        $this->key = $raw;
    }

    /**
     * Returns a new base64-encoded key. Generate one, store it outside the
     * repository, and reuse it — a new key cannot read old ciphertexts.
     */
    public static function generateKey(): string
    {
        return base64_encode(random_bytes(self::KEY_BYTES));
    }

    /** Encrypts a value for storage. The result is base64. */
    public function encrypt(#[SensitiveParameter] string $data): string
    {
        return base64_encode($this->seal($data));
    }

    /** Returns the plaintext, or null when the input was tampered with or is not ours. */
    public function decrypt(string $data): ?string
    {
        $raw = base64_decode($data, true);

        return $raw === false ? null : $this->open($raw);
    }

    /** Encrypts a value for use in a URL. The result contains only [A-Za-z0-9_-]. */
    public function encryptForUrl(#[SensitiveParameter] string $data): string
    {
        return rtrim(strtr(base64_encode($this->seal($data)), '+/', '-_'), '=');
    }

    /** Returns the plaintext, or null when the input was tampered with or is not ours. */
    public function decryptFromUrl(string $data): ?string
    {
        $padded = strtr($data, '-_', '+/');
        $padded .= str_repeat('=', (4 - strlen($padded) % 4) % 4);

        $raw = base64_decode($padded, true);

        return $raw === false ? null : $this->open($raw);
    }

    /** Keeps the key out of var_dump() and stack traces. */
    public function __debugInfo(): array
    {
        return ['key' => '***'];
    }

    private function seal(string $data): string
    {
        $nonce = random_bytes(self::NONCE_BYTES);

        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $data,
            self::VERSION . $nonce,
            $nonce,
            $this->key,
        );

        return self::VERSION . $nonce . $ciphertext;
    }

    private function open(string $raw): ?string
    {
        $headerLength = strlen(self::VERSION) + self::NONCE_BYTES;

        if (strlen($raw) <= $headerLength || !str_starts_with($raw, self::VERSION)) {
            return null;
        }

        $nonce = substr($raw, strlen(self::VERSION), self::NONCE_BYTES);
        $ciphertext = substr($raw, $headerLength);

        try {
            $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
                $ciphertext,
                self::VERSION . $nonce,
                $nonce,
                $this->key,
            );
        } catch (SodiumException) {
            return null;
        }

        return $plaintext === false ? null : $plaintext;
    }
}
