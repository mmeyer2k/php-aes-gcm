<?php

declare(strict_types=1);

namespace Mmeyer2k\AesGcm;

use Exception;
use SensitiveParameter;

class AesGcm
{
    /**
     * @var string[] $rotated
     */
    public array $rotated = [];
    public bool $fallback = false;

    public function __construct(
        #[SensitiveParameter] private readonly string $key,
        #[SensitiveParameter] private readonly string $context = '',
    )
    {
    }

    public function encrypt(
        #[SensitiveParameter] string $plaintext,
        #[SensitiveParameter] string $aad = '',
    ): string
    {
        $ivr = random_bytes(12);

        if (sodium_crypto_aead_aes256gcm_is_available() && !$this->fallback) {
            $msg = sodium_crypto_aead_aes256gcm_encrypt(
                message: $plaintext,
                additional_data: $aad,
                nonce: $ivr,
                key: $this->hkdf($this->key, $ivr),
            );

            return $ivr . $msg;
        }

        $tag = '';

        $msg = openssl_encrypt(
            data: $plaintext,
            cipher_algo: 'aes-256-gcm',
            passphrase: $this->hkdf($this->key, $ivr),
            options: OPENSSL_RAW_DATA,
            iv: $ivr,
            tag: $tag,
            aad: $aad,
        );

        return $ivr . $msg . $tag;
    }

    public function decrypt(
        #[SensitiveParameter] string $ciphertext,
        #[SensitiveParameter] string $aad = '',
    ): string
    {
        $ivr = substr($ciphertext, 0, 12);

        foreach ([$this->key, ...$this->rotated] as $key) {
            if (sodium_crypto_aead_aes256gcm_is_available() && !$this->fallback) {
                $msg = sodium_crypto_aead_aes256gcm_decrypt(
                    ciphertext: substr($ciphertext, 12),
                    additional_data: $aad,
                    nonce: $ivr,
                    key: $this->hkdf($key, $ivr),
                );
            } else {
                $tag = substr($ciphertext, -16);

                $msg = openssl_decrypt(
                    data: substr($ciphertext, 12, -16),
                    cipher_algo: 'aes-256-gcm',
                    passphrase: $this->hkdf($key, $ivr),
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

    private function hkdf(
        #[SensitiveParameter] string $key,
        #[SensitiveParameter] string $ivr,
    ): string
    {
        $key = base64_decode($key);

        if (strlen($key) !== SODIUM_CRYPTO_AEAD_AES256GCM_KEYBYTES) {
            throw new Exception("AESGcm: key must be 32 bytes");
        }

        return hash_hkdf(
            algo: 'sha3-256',
            key: $key,
            length: 0,
            info: $this->context . $ivr,
            salt: '' // intentionally blank
        );
    }
}
