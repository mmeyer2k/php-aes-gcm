# php-aes-gcm
A compact AES-256 GCM implementation for PHP 8.0+

## Install
To take advantage of security features added in PHP 8.2, install from the main branch.
```bash
composer require mmeyer2k/php-aes-gcm
```

To use a version compatible with all versions of PHP 8.
```bash
composer require "mmeyer2k/php-aes-gcm:dev-php-8.x"
```


## Basic usage
```php
use Mmeyer2k\AesGcm\AesGcm;

$msg = 'AAAAAAAA';
$key = 'BBBBBBBB';

$enc = AesGcm::encrypt($msg, $key);

$dec = AesGcm::decrypt($enc, $key);
```
