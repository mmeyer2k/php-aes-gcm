# php-aes-gcm

A compact and foolproof AES-256 GCM implementation for PHP powered by `ext-sodium`.
On systems without `AES-NI` support, this library falls back to using `ext-openssl`.
Data encryption is cross-compatible between both extensions.

## Install

To take advantage of the cool features in PHP 8.2+, install from the main branch.
```bash
composer require "mmeyer2k/php-aes-gcm:dev-main"
```

If you need to support PHP versions prior to 8.2, install from the `legacy` branch.
```bash
composer require "mmeyer2k/php-aes-gcm:dev-legacy"
```

## Basic usage

```php
$key = '\+YoUr\+32\+ByTe\+BaSe64\+EnCoDeD\+kEy\+GoEs\+HeRe\+';

$msg = 'Hello World!';

$aes = new \Mmeyer2k\AesGcm\AesGcm($key);

$enc = $aes->encrypt($msg);

$dec = $aes->decrypt($enc);

echo $dec;
```

## Keys

This library expects 32 byte keys encoded with base64.
Keys should originate from secure sources of randomness to ensure the highest degree of protection.

In PHP:
```php
echo base64_decode(random_bytes(32));
```

In BaSH:
```bash
head -c 32 /dev/urandom | base64 -w 0 | xargs echo
```

## Other Usages

### Key Contexts

Key contextualization allows for one key to be used in many domains.
Diversity of contexts help lowers the rate of key exhaustion.
```php
$aes = new \Mmeyer2k\AesGcm\AesGcm($key, 'sessions');
// or...
$aes = new \Mmeyer2k\AesGcm\AesGcm($key, 'passport photos');
```

Serialized contexts offer the highest protection, ensuring that key collisions happen near the theoretical minimum.
```php
$aes = new \Mmeyer2k\AesGcm\AesGcm($key, "document:$id");
```

### Additional Authenticated Data (AAD)

AAD data is extra information that is authenticated but unencrypted.
Both the AAD and ciphertext must be present for decryption to proceed.
```php
$aes = new \Mmeyer2k\AesGcm\AesGcm($key);

$aad = '...some extra information...'

$enc = $aes->encrypt($msg, $aad);

$dec = $aes->decrypt($enc, $aad);
```

### Native Key Rotation

Supply an array of rotated keys which will be attempted if the primary key fails to decrypt the ciphertext.
```php
$aes = new \Mmeyer2k\AesGcm\AesGcm($key);

$aes->rotated = [
    'key 1',
    'key 2',
    'key 3',
];

$dec = $aes->decrypt($ciphertext);
```
