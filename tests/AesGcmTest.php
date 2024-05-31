<?php

declare(strict_types=1);

use \PHPUnit\Framework\TestCase;
use \Mmeyer2k\AesGcm\AesGcm;

final class AesGcmTest extends TestCase
{
    public function testBasicEncryption(): void
    {
        $msg = 'AAAAAAAA';
        $key = 'BBBBBBBB';

        $enc = AesGcm::encrypt($msg, $key);

        $dec = AesGcm::decrypt($enc, $key);

        $this->assertSame($dec, $msg);
    }

    public function testBadChecksum(): void
    {
        $rnd = random_bytes(32);

        $out = AesGcm::decrypt($rnd, $rnd);

        $this->assertFalse($out);
    }

    public function testAadAuthentication(): void
    {
        $aad = 'authenticated meta data';
        $msg = 'secret message';
        $key = 'shhhhhhh';

        $enc = AesGcm::encrypt($msg, $key, $aad);

        $dec = AesGcm::decrypt($enc, $key, $aad);

        $this->assertSame($msg, $dec);

        $broken = AesGcm::decrypt($enc, $key, $aad . ' contamination');

        $this->assertFalse($broken);
    }
}
