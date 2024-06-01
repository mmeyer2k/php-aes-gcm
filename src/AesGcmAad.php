<?php

declare(strict_types=1);

namespace Mmeyer2k\AesGcm;

class AesGcmAad
{
    /**
     * @param string $msg
     * @param string $key
     * @param string $aad
     * @return string
     * @throws AesGcmException
     */
    public static function encrypt(string $msg, string $key, string $aad): string
    {
        $msg = AesGcm::encrypt($msg, $key, $aad);

        $len = strlen($aad);

        return $msg . $aad . pack('N', $len);
    }

    /**
     * @param string $msg
     * @param string $key
     * @return array<string, string>
     * @throws AesGcmException
     */
    public static function decrypt(string $msg, string $key): array
    {
        $len = unpack('N', substr($msg, -4))[1];

        $aad = substr($msg, -(4 + $len), -4);

        $msg = substr($msg, 0, -(4 + $len));

        $msg = AesGcm::decrypt($msg, $key, $aad);

        return [$msg, $aad];
    }
}
