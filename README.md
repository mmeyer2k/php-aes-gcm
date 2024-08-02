# php-aes-gcm
A compact and foolproof AES-256 GCM implementation for PHP.

## Install

To take advantage of security features in PHP 8.2+, install from the main branch.
```bash
composer require mmeyer2k/php-aes-gcm
```

If you need to support PHP versions prior to 8.2, install from the `legacy` branch.
```bash
composer require "mmeyer2k/php-aes-gcm:dev-legacy"
```

Encrypted data is cross-compatible between the two branches.
The only differences are the presence of `#\SensitiveParamter` in the function signatures and usage of named parameters for clarity.

## Basic usage

```php
use Mmeyer2k\AesGcm\AesGcm;

$msg = 'AAAAAAAA';
$key = 'BBBBBBBB';

$enc = AesGcm::encrypt($msg, $key);

$dec = AesGcm::decrypt($enc, $key);
```

## Keys

For full security, 256-bit keys should be generated using a cryptographically secure random number generator.

In PHP
```php
$key = random_bytes(32);
```

In the shell (with base64 encoding)
```bash
head -c 32 /dev/urandom | base64 -w 0 | xargs echo
```

In general, it is best to use some form of encoding when storing keys in a string format.
This library expects all keys to be decoded before use.