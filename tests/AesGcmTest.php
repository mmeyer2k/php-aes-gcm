<?php

declare(strict_types=1);

use Mmeyer2k\AesGcm\AesGcmException;
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

        $this->expectException(AesGcmException::class);

        AesGcm::decrypt($rnd, $rnd);
    }

    public function testBadKey(): void
    {
        $this->expectException(ValueError::class);

        AesGcm::encrypt('AAAA', '');
    }

    public function testAadAuthentication(): void
    {
        $aad = 'authenticated meta data';
        $msg = 'secret message';
        $key = 'shhhhhhh';

        $enc = AesGcm::encrypt($msg, $key, $aad);

        $dec = AesGcm::decrypt($enc, $key, $aad);

        $this->assertSame($msg, $dec);

        $this->expectException(AesGcmException::class);

        AesGcm::decrypt($enc, $key, $aad . ' contamination');
    }
}
