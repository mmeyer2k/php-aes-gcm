<?php

declare(strict_types=1);

namespace Mmeyer2k\AesGcm;

class AesGcmAad
{
    public static function encrypt(string $msg, string $key, string $aad): string
    {
        $msg = AesGcm::encrypt($msg, $key, $aad);

        $len = strlen($aad);

        return $msg . $aad . pack('N', $len);
    }

    public static function decrypt(string $msg, string $key): array // @phpstan-ignore-line
    {
        $len = unpack('N', substr($msg, -4))[1]; // @phpstan-ignore-line

        $aad = substr($msg, -(4 + $len), -4);

        $msg = substr($msg, 0, -(4 + $len));

        $msg = AesGcm::decrypt($msg, $key, $aad);

        return [$msg, $aad];
    }
}
