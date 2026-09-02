<?php

declare(strict_types=1);

namespace UmitYatarkalkmaz\Tests;

use InvalidArgumentException;
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

        self::assertStringNotContainsString($key, print_r(new Encryption($key), true));
    }
}
