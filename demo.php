<?php

require 'vendor/autoload.php';

$key = '\+YoUr\+32\+ByTe\+BaSe64\+EnCoDeD\+kEy\+GoEs\+HeRe\+';

$msg = 'Hello World!';

$aes = new \Mmeyer2k\AesGcm\AesGcm($key);

$enc = $aes->encrypt($msg);

$dec = $aes->decrypt($enc);

var_dump([
    base64_encode($enc), 
    $dec,
]);
