<?php

declare(strict_types=1);

namespace Mmeyer2k\AesGcm;

use Exception;

class AesGcm
{
    public bool $fallback = false;
    private readonly array $keys;

    /**
     * @param string|string[] $keys
     */
    public function __construct(string|array $keys)
    {
        $this->keys = is_string($keys) ? [$keys] : $keys;
    }

    public function encrypt(
        string $plaintext,
        string $aad = '',
    ): string
    {
        $ivr = random_bytes(12);

        $tag = '';

        if (sodium_crypto_aead_aes256gcm_is_available() && !$this->fallback) {
            $msg = sodium_crypto_aead_aes256gcm_encrypt(
                message: $plaintext,
                additional_data: $aad,
                nonce: $ivr,
                key: $this->keys[0],
            );
        } else {
            $msg = openssl_encrypt(
                data: $plaintext,
                cipher_algo: 'aes-256-gcm',
                passphrase: $this->keys[0],
                options: OPENSSL_RAW_DATA,
                iv: $ivr,
                tag: $tag,
                aad: $aad,
            );
        }

        if (false === $msg) {
            throw new Exception("AESGcm: Failed to encrypt message");
        }

        return $ivr . $msg . $tag;
    }

    public function decrypt(
        string $ciphertext,
        string $aad = '',
    ): string
    {
        $ivr = substr($ciphertext, 0, 12);

        foreach ($this->keys as $key) {
            if (sodium_crypto_aead_aes256gcm_is_available() && !$this->fallback) {
                $msg = sodium_crypto_aead_aes256gcm_decrypt(
                    ciphertext: substr($ciphertext, 12),
                    additional_data: $aad,
                    nonce: $ivr,
                    key: $key,
                );
            } else {
                $tag = substr($ciphertext, -16);

                $msg = openssl_decrypt(
                    data: substr($ciphertext, 12, -16),
                    cipher_algo: 'aes-256-gcm',
                    passphrase: $key,
                    options: OPENSSL_RAW_DATA,
                    iv: $ivr,
                    tag: $tag,
                    aad: $aad,
                );
            }

            if (false !== $msg) {
                return $msg;
            }
        }

        throw new Exception("AESGcm: Failed to decrypt message");
    }
}
