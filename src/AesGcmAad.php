<?php

declare(strict_types=1);

namespace Mmeyer2k\AesGcm;

class AesGcmAad
{
    public static function encrypt(string $data, string $key, string $aad): string
    {
        $msg = AesGcm::encrypt($data, $key, $aad);

        $len = strlen($aad);

        return $msg . $aad . pack('N', $len);
    }

    public static function decrypt(string $data, string $key): array
    {
        $len = unpack('N', substr($data, -4))[1];

        $aad = substr($data, -(4 + $len), -4);

        $msg = substr($data, 0, -(4 + $len));

        $msg = AesGcm::decrypt($msg, $key, $aad);

        return [$msg, $aad];
    }
}
