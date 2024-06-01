<?php

declare(strict_types=1);

namespace Mmeyer2k\AesGcm;

use SensitiveParameter;

class AesGcm
{
    public static function encrypt(
        #[SensitiveParameter] string $plaintext,
        #[SensitiveParameter] string $key,
        #[SensitiveParameter] string $aad = ''
    ): string
    {
        $tag = '';

        $ivr = random_bytes(16);

        $msg = openssl_encrypt(
            data: $plaintext,
            cipher_algo: 'aes-256-gcm',
            passphrase: self::key($key, $ivr, $aad),
            options: OPENSSL_RAW_DATA,
            iv: $ivr,
            tag: $tag,
            aad: $aad,
        );

        if (false === $msg) {
            throw new AesGcmException;
        }

        return $tag . $ivr . $msg;
    }

    public static function decrypt(
        #[SensitiveParameter] string $ciphertext,
        #[SensitiveParameter] string $key,
        #[SensitiveParameter] string $aad = ''
    ): string
    {
        $tag = substr($ciphertext, 0, 16);

        $ivr = substr($ciphertext, 16, 16);

        $msg = openssl_decrypt(
            data: substr($ciphertext, 32),
            cipher_algo: 'aes-256-gcm',
            passphrase: self::key($key, $ivr, $aad),
            options: OPENSSL_RAW_DATA,
            iv: $ivr,
            tag: $tag,
            aad: $aad,
        );

        if (false === $msg) {
            throw new AesGcmException;
        }

        return $msg;
    }

    private static function key(
        #[SensitiveParameter] string $key,
        #[SensitiveParameter] string $ivr,
        #[SensitiveParameter] string $aad = ''
    ): string
    {
        return hash_hkdf(
            algo: 'sha3-256',
            key: $key,
            length: 32,
            info: $aad,
            salt: $ivr,
        );
    }
}
