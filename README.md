# php-aes-gcm

A compact and foolproof AES-256 GCM implementation for PHP powered by `ext-sodium`.
On systems without `AES-NI` support, this library falls back to using `ext-openssl`.
Data encryption is cross-compatible between both extensions.

## Install

To take advantage of the cool features in PHP 8.2+, install from the main branch.
```bash
composer require "mmeyer2k/php-aes-gcm:dev-main"
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

To rotate keys, pass an array of key strings into the constructor.
The first key (index 0) will be used for encryption.
All keys will be attempted when decrypting.
```php
$old = [
    'key 1',
    'key 2',
    'key 3',
];

$aes = new \Mmeyer2k\AesGcm\AesGcm($keys);

$dec = $aes->decrypt($ciphertext);
```
