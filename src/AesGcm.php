<?php

declare(strict_types=1);

namespace Mmeyer2k\AesGcm;

use SensitiveParameter;

class AesGcm
{
    public static function encrypt(
        string $plaintext,
        string $key,
        string $aad = ''
    ): string
    {
        $tag = '';

        $ivr = random_bytes(16);

        $msg = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            self::key($key, $ivr, $aad),
            OPENSSL_RAW_DATA,
            $ivr,
            $tag,
            $aad,
        );

        if (false === $msg) {
            throw new AesGcmException;
        }

        return $tag . $ivr . $msg;
    }

    public static function decrypt(
        string $ciphertext,
        string $key,
        string $aad = ''
    ): string
    {
        $tag = substr($ciphertext, 0, 16);

        $ivr = substr($ciphertext, 16, 16);

        $msg = openssl_decrypt(
            substr($ciphertext, 32),
            'aes-256-gcm',
            self::key($key, $ivr, $aad),
            OPENSSL_RAW_DATA,
            $ivr,
            $tag,
            $aad,
        );

        if (false === $msg) {
            throw new AesGcmException;
        }

        return $msg;
    }

    private static function key(
        string $key,
        string $ivr,
        string $aad = ''
    ): string
    {
        return hash_hkdf(
            'sha3-256',
            $key,
            32,
            $aad,
            $ivr,
        );
    }
}
