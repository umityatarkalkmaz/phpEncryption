# Encryption

Authenticated encryption for values you store in a database or put in a URL.

Uses XChaCha20-Poly1305 with a random nonce per message, so the same plaintext
never produces the same ciphertext twice, and any modification to a ciphertext
is detected instead of decrypting into garbage.

## Requirements

PHP 8.2 or newer, with `ext-sodium` (bundled with PHP since 7.2).

## Installation

```bash
composer require umityatarkalkmaz/encryption
```

## Getting a key

A passphrase is not a key. Generate one:

```php
use UmitYatarkalkmaz\Encryption;

echo Encryption::generateKey();   // base64 of 32 random bytes
```

Store it outside your repository — an environment variable or a config file that
is not committed — and reuse it. A different key cannot read old ciphertexts,
and losing the key loses the data.

```php
$key = $_ENV['APP_ENCRYPTION_KEY'] ?? null;

if (!is_string($key)) {
    throw new RuntimeException('APP_ENCRYPTION_KEY is not set.');
}

$encryption = new Encryption($key);
```

Check the variable before passing it. The constructor is typed `string`, so an
unset `$_ENV['APP_ENCRYPTION_KEY']` raises a `TypeError`, not the
`InvalidArgumentException` you would be catching. That exception is for a key
that arrives as a string but is not base64, or does not decode to exactly 32
bytes.

## Usage

```php
// For a database column
$stored = $encryption->encrypt('user id');
$value  = $encryption->decrypt($stored);      // 'user id', or null

// For a URL
$token = $encryption->encryptForUrl('42');    // only [A-Za-z0-9_-]
$id    = $encryption->decryptFromUrl($token); // '42', or null
```

Both `decrypt()` and `decryptFromUrl()` return `null` when the input was
tampered with, encrypted under a different key, or is not a ciphertext at all.
Always check for `null` — a `null` here means someone changed the value:

```php
$id = $encryption->decryptFromUrl($_GET['id'] ?? '');

if ($id === null) {
    http_response_code(400);
    return;
}
```

## Keeping the key out of your output

The constructor parameter is marked `#[SensitiveParameter]`, so PHP prints
`Object(SensitiveParameterValue)` instead of the key in any stack trace that
crosses it. `__debugInfo()` replaces the key with `***` for `var_dump()` and
`print_r()`, and `serialize()` throws a `LogicException` rather than writing the
raw key into a session file, a cache entry or a log line.

None of that is containment. The decoded key lives in the object for as long as
the object does, and it is never zeroed: PHP strings are immutable and copied
freely, so there is no point at which the bytes can be reliably overwritten. A
core dump, a memory-reading debugger, a swap file, or `ReflectionProperty` still
reach it. Treat process memory as readable by anything that can already run code
in it, and keep the key out of the places you *can* control — version control,
logs, and error pages.

## What this does not do

Encryption hides a value; it does not make it trustworthy on its own, and it is
not a substitute for an access check. A visitor who holds a valid encrypted id
still needs to be allowed to see the record it names.

## License

MIT. See [LICENSE](LICENSE).
