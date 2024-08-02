# php-aes-gcm
A compact and foolproof AES-256 GCM implementation for PHP.

## Install
To take advantage of security features added in PHP 8.2, install from the main branch.
```bash
composer require mmeyer2k/php-aes-gcm
```

To use a version compatible with all versions of PHP 8.
```bash
composer require "mmeyer2k/php-aes-gcm:dev-php-8.x"
```

To use a version compatible with PHP 7.4.
```bash
composer require "mmeyer2k/php-aes-gcm:dev-php-7.x"
```


## Basic usage
```php
use Mmeyer2k\AesGcm\AesGcm;

$msg = 'AAAAAAAA';
$key = 'BBBBBBBB';

$enc = AesGcm::encrypt($msg, $key);

$dec = AesGcm::decrypt($enc, $key);
```
