<?php

declare(strict_types=1);

namespace UmitYatarkalkmaz\Tests;

use InvalidArgumentException;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use UmitYatarkalkmaz\Encryption;

final class EncryptionTest extends TestCase
{
    private Encryption $encryption;

    protected function setUp(): void
    {
        $this->encryption = new Encryption(Encryption::generateKey());
    }

    #[DataProvider('providePlaintexts')]
    public function testStorageRoundTrip(string $plaintext): void
    {
        self::assertSame($plaintext, $this->encryption->decrypt($this->encryption->encrypt($plaintext)));
    }

    #[DataProvider('providePlaintexts')]
    public function testUrlRoundTrip(string $plaintext): void
    {
        self::assertSame($plaintext, $this->encryption->decryptFromUrl($this->encryption->encryptForUrl($plaintext)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function providePlaintexts(): iterable
    {
        yield 'short' => ['user id'];
        yield 'numeric id' => ['42'];
        yield 'empty string' => [''];
        yield 'unicode' => ['Şeker Ağacı — ünlü'];
        yield 'null bytes' => ["a\x00b\x00c"];
        yield 'binary' => ["\x00\x01\x02\xff\xfe"];
        yield 'long' => [str_repeat('long payload ', 500)];
        yield 'json' => ['{"id":42,"role":"admin"}'];
    }

    public function testTheSamePlaintextEncryptsDifferentlyEveryTime(): void
    {
        $first = $this->encryption->encrypt('user id');
        $second = $this->encryption->encrypt('user id');

        self::assertNotSame($first, $second);
        self::assertSame('user id', $this->encryption->decrypt($first));
        self::assertSame('user id', $this->encryption->decrypt($second));
    }

    public function testUrlCiphertextIsSafeToPutInAQueryString(): void
    {
        $encrypted = $this->encryption->encryptForUrl('user id');

        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $encrypted);
        self::assertSame($encrypted, rawurlencode($encrypted));
    }

    public function testATamperedCiphertextIsRejectedRatherThanDecrypted(): void
    {
        $encrypted = $this->encryption->encrypt('role=user');
        $raw = base64_decode($encrypted, true);

        self::assertIsString($raw);

        $raw[strlen($raw) - 1] = $raw[strlen($raw) - 1] === "\x00" ? "\x01" : "\x00";

        self::assertNull($this->encryption->decrypt(base64_encode($raw)));
    }

    public function testATruncatedCiphertextIsRejected(): void
    {
        $encrypted = $this->encryption->encrypt('user id');
        $raw = (string) base64_decode($encrypted, true);

        self::assertNull($this->encryption->decrypt(base64_encode(substr($raw, 0, 10))));
    }

    public function testAnotherKeyCannotRead(): void
    {
        $other = new Encryption(Encryption::generateKey());

        self::assertNull($other->decrypt($this->encryption->encrypt('user id')));
    }

    #[DataProvider('provideUnusableCiphertexts')]
    public function testUnusableInputReturnsNull(string $input): void
    {
        self::assertNull($this->encryption->decrypt($input));
        self::assertNull($this->encryption->decryptFromUrl($input));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideUnusableCiphertexts(): iterable
    {
        yield 'empty' => [''];
        yield 'not base64' => ['!!!not base64!!!'];
        yield 'base64 of nothing useful' => ['AAAA'];
        yield 'wrong version byte' => [base64_encode("\x02" . str_repeat("\x00", 40))];
    }

    public function testGeneratedKeysAreDistinctAndUsable(): void
    {
        $first = Encryption::generateKey();
        $second = Encryption::generateKey();

        self::assertNotSame($first, $second);
        self::assertSame(32, strlen((string) base64_decode($first, true)));
        self::assertSame('ok', (new Encryption($first))->decrypt((new Encryption($first))->encrypt('ok')));
    }

    #[DataProvider('provideBadKeys')]
    public function testUnusableKeyIsRejectedAtConstruction(string $key, string $expectedMessage): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches($expectedMessage);

        new Encryption($key);
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideBadKeys(): iterable
    {
        yield 'passphrase' => ['MY-SECRET-KEY', '/passphrase is not a key/'];
        yield 'empty' => ['', '/exactly 32 bytes/'];
        yield 'too short' => [base64_encode(random_bytes(16)), '/exactly 32 bytes/'];
        yield 'too long' => [base64_encode(random_bytes(64)), '/exactly 32 bytes/'];
        yield 'not base64' => ['!!!!', '/base64-encoded/'];
    }

    public function testTheKeyDoesNotLeakThroughVarDump(): void
    {
        $key = Encryption::generateKey();
        $raw = base64_decode($key, true);

        // The property holds the decoded bytes, so asserting on the base64
        // string would pass even with __debugInfo() deleted.
        self::assertIsString($raw);

        $dumped = print_r(new Encryption($key), true);

        self::assertStringNotContainsString($raw, $dumped);
        self::assertStringNotContainsString($key, $dumped);
    }

    public function testAnInstanceCannotBeSerialized(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/must not be serialized/');

        serialize(new Encryption(Encryption::generateKey()));
    }

    public function testAnInstanceCannotBeUnserialized(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/cannot be unserialized/');

        unserialize('O:27:"UmitYatarkalkmaz\\Encryption":1:{s:3:"key";s:3:"abc";}');
    }

    public function testStorageDecryptAcceptsOnlyTheEncodingEncryptProduces(): void
    {
        $encrypted = $this->encryptUsingAlphabetSpecificCharacters('ab', false);

        self::assertSame('ab', $this->encryption->decrypt($encrypted));

        // Whitespace: base64_decode() tolerates it even in strict mode.
        self::assertNull($this->encryption->decrypt(
            substr($encrypted, 0, 8) . "\n" . substr($encrypted, 8),
        ));
        self::assertNull($this->encryption->decrypt(' ' . $encrypted));

        // The other alphabet decodes to the same bytes.
        self::assertNull($this->encryption->decrypt(strtr($encrypted, '+/', '-_')));

        // Padding beyond what the length calls for.
        self::assertNull($this->encryption->decrypt($encrypted . '='));
        self::assertNull($this->encryption->decrypt(rtrim($encrypted, '=')));

        // The final character carries bits no byte of the plaintext uses.
        self::assertNull($this->encryption->decrypt(self::flipUnusedPaddingBit($encrypted, false)));
    }

    public function testUrlDecryptAcceptsOnlyTheEncodingEncryptForUrlProduces(): void
    {
        $token = $this->encryptUsingAlphabetSpecificCharacters('ab', true);

        self::assertSame('ab', $this->encryption->decryptFromUrl($token));

        self::assertNull($this->encryption->decryptFromUrl(
            substr($token, 0, 8) . "\n" . substr($token, 8),
        ));
        self::assertNull($this->encryption->decryptFromUrl(' ' . $token));

        // The standard alphabet is not the one encryptForUrl() emits.
        self::assertNull($this->encryption->decryptFromUrl(strtr($token, '-_', '+/')));

        // encryptForUrl() strips padding, so any '=' is somebody else's addition.
        self::assertNull($this->encryption->decryptFromUrl($token . '='));
        self::assertNull($this->encryption->decryptFromUrl($token . '=='));

        self::assertNull($this->encryption->decryptFromUrl(self::flipUnusedPaddingBit($token, true)));
    }

    /**
     * Encrypts until the result actually uses a character the other alphabet
     * spells differently, so swapping alphabets is a real change to test.
     */
    private function encryptUsingAlphabetSpecificCharacters(string $plaintext, bool $url): string
    {
        for ($attempt = 0; $attempt < 200; $attempt++) {
            $encoded = $url
                ? $this->encryption->encryptForUrl($plaintext)
                : $this->encryption->encrypt($plaintext);

            if (strpbrk($encoded, $url ? '-_' : '+/') !== false) {
                return $encoded;
            }
        }

        self::fail('No ciphertext used an alphabet-specific character in 200 attempts.');
    }

    /**
     * Rewrites the last character carrying data so it decodes to the same bytes
     * with the unused low bits set, which is what a canonical check must catch.
     */
    private static function flipUnusedPaddingBit(string $encoded, bool $url): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' . ($url ? '-_' : '+/');
        $position = strlen(rtrim($encoded, '=')) - 1;
        $index = strpos($alphabet, $encoded[$position]);

        self::assertIsInt($index);

        $encoded[$position] = $alphabet[$index ^ 1];

        return $encoded;
    }
}
