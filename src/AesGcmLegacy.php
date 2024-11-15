<?php

declare(strict_types=1);

namespace Mmeyer2k\AesGcm;

use Exception;

class AesGcm
{
    /**
     * @var string[] $rotated
     */
    public array $rotated;

    private string $key;

    public bool $fallback = false;

    public function __construct(
        string $key,
        array $rotated
    )
    {
        $this->key = $key;
        $this->rotated = $rotated;
    }

    public function encrypt(
        string $plaintext,
        string $aad = ''
    ): string
    {
        $ivr = random_bytes(16);

        $tag = '';

        if (sodium_crypto_aead_aes256gcm_is_available() && !$this->fallback) {
            $msg = sodium_crypto_aead_aes256gcm_encrypt(
                $plaintext,
                $aad,
                $ivr,
                $this->key,
            );
        } else {
            $msg = openssl_encrypt(
                $plaintext,
                'aes-256-gcm',
                $this->key,
                OPENSSL_RAW_DATA,
                $ivr,
                $tag,
                $aad,
            );
        }

        if (false === $msg) {
            throw new Exception("AESGcm: Failed to encrypt message");
        }

        return $ivr . $msg . $tag;
    }

    public function decrypt(
        string $ciphertext,
        string $aad = ''
    ): string
    {
        $ivr = substr($ciphertext, 0, 16);

        foreach ([$this->key, ...$this->rotated] as $key) {
            if (sodium_crypto_aead_aes256gcm_is_available() && !$this->fallback) {
                $msg = sodium_crypto_aead_aes256gcm_decrypt(
                    substr($ciphertext, 16),
                    $aad,
                    substr($ivr, -12),
                    $key,
                );
            } else {
                $tag = substr($ciphertext, -16);

                $msg = openssl_decrypt(
                    substr($ciphertext, 16, -16),
                    'aes-256-gcm',
                    $key,
                    OPENSSL_RAW_DATA,
                    substr($ivr, -12),
                    $tag,
                    $aad,
                );
            }

            if (false !== $msg) {
                return $msg;
            }
        }

        throw new Exception("AESGcm: Failed to decrypt message");
    }
}
