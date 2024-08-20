<?php

require 'vendor/autoload.php';

$msg = 'Hello World!';

$aes = new \Mmeyer2k\AesGcm\AesGcm('[ ... your secret key goes here ...]');

$enc = $aes->encrypt($msg);

$dec = $aes->decrypt($enc);

var_dump([
    base64_encode($enc), 
    $dec,
]);
