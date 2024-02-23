# php-aes-gcm
A compact AES-256 GCM implementation for PHP 8.2+

## Install

## Basic usage
```php
use Mmeyer2k\AesGcm\AesGcm;

$msg = 'AAAAAAAA';
$key = 'BBBBBBBB';

$enc = AesGcm::encrypt($msg, $key);

$dec = AesGcm::decrypt($enc, $key);
```
