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
        $this->expectException(\Exception::class);

        AesGcm::decrypt(random_bytes(32), random_bytes(32));
    }
}
