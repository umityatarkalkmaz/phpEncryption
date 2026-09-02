<?php

declare(strict_types=1);

namespace UmitYatarkalkmaz;

use InvalidArgumentException;
use LogicException;
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
        return self::encode($this->seal($data), false);
    }

    /** Returns the plaintext, or null when the input was tampered with or is not ours. */
    public function decrypt(string $data): ?string
    {
        $raw = self::decodeCanonical($data, false);

        return $raw === null ? null : $this->open($raw);
    }

    /** Encrypts a value for use in a URL. The result contains only [A-Za-z0-9_-]. */
    public function encryptForUrl(#[SensitiveParameter] string $data): string
    {
        return self::encode($this->seal($data), true);
    }

    /** Returns the plaintext, or null when the input was tampered with or is not ours. */
    public function decryptFromUrl(string $data): ?string
    {
        $raw = self::decodeCanonical($data, true);

        return $raw === null ? null : $this->open($raw);
    }

    /** Keeps the key out of var_dump() and stack traces. */
    public function __debugInfo(): array
    {
        return ['key' => '***'];
    }

    /**
     * Serializing would copy the raw key into whatever holds the string — a
     * session file, a cache entry, a log line. Construct from the key instead.
     *
     * @return array<string, mixed>
     *
     * @throws LogicException always
     */
    public function __serialize(): array
    {
        throw new LogicException(
            'An Encryption instance holds a secret key and must not be serialized; store the key itself instead.',
        );
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws LogicException always
     */
    public function __unserialize(array $data): void
    {
        throw new LogicException(
            'An Encryption instance cannot be unserialized; construct it from the key instead.',
        );
    }

    private function seal(#[SensitiveParameter] string $data): string
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

    /** @param bool $url true for base64url without padding, false for standard base64 */
    private static function encode(string $raw, bool $url): string
    {
        $encoded = base64_encode($raw);

        return $url ? rtrim(strtr($encoded, '+/', '-_'), '=') : $encoded;
    }

    /**
     * Decodes only the one spelling encode() would have produced, and returns
     * null for every other spelling of the same bytes.
     *
     * base64_decode() in strict mode still accepts embedded whitespace, and it
     * ignores the unused bits in a final character, so a single ciphertext has
     * many accepted encodings. That turns an authenticated ciphertext back into
     * a malleable string: a token can be reshaped in transit and still decrypt,
     * which breaks any caller that treats the encoded form as an identity — a
     * cache key, a replay list, a uniqueness check. Re-encoding and demanding a
     * byte-identical match leaves exactly one accepted spelling.
     *
     * @param bool $url true for base64url without padding, false for standard base64
     */
    private static function decodeCanonical(string $data, bool $url): ?string
    {
        $standard = $data;

        if ($url) {
            $standard = strtr($standard, '-_', '+/');
            $standard .= str_repeat('=', (4 - strlen($standard) % 4) % 4);
        }

        $raw = base64_decode($standard, true);

        if ($raw === false || self::encode($raw, $url) !== $data) {
            return null;
        }

        return $raw;
    }
}
