<?php

declare(strict_types=1);

namespace Mmeyer2k\AesGcm;

use Exception;

class AesGcm
{
    /**
     * @var string[] $rotated
     */
    public array $rotated = [];
    public bool $fallback = false;

    private string $key;
    private string $context;

    public function __construct(
        string $key,
        string $context = ''
    )
    {
        $this->key = $key;
        $this->context = $context;
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
                substr($ivr, -12),
                $this->hkdf($this->key, $ivr),
            );
        } else {
            $msg = openssl_encrypt(
                $plaintext,
                'aes-256-gcm',
                $this->hkdf($this->key, $ivr),
                OPENSSL_RAW_DATA,
                substr($ivr, -12),
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
                    $this->hkdf($key, $ivr),
                );
            } else {
                $tag = substr($ciphertext, -16);

                $msg = openssl_decrypt(
                    substr($ciphertext, 16, -16),
                    'aes-256-gcm',
                    $this->hkdf($key, $ivr),
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

    private function hkdf(
        string $key,
        string $ivr
    ): string
    {
        $key = base64_decode($key);

        if (strlen($key) !== SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES) {
            throw new Exception("AESGcm: key must be 32 bytes");
        }

        return hash_hkdf(
            'sha3-256',
            $key,
            0,
            $this->context . $ivr,
            '' // intentionally blank
        );
    }
}
