<?php

if (PHP_VERSION_ID > 80200) {
    require 'src/AesGcm.php';
} else {
    require 'src/AesGcmLegacy.php';
}