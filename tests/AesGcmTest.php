<?php

declare(strict_types=1);

use Mmeyer2k\AesGcm\AesGcm;
use PHPUnit\Framework\TestCase;

final class AesGcmTest extends TestCase
{
    private static function gcmConstrcutor(): AesGcm
    {
        $key = base64_encode(random_bytes(32));

        return new AesGcm($key);
    }

    public function testBasicEncryption(): void
    {
        $gcm = self::gcmConstrcutor();
        $msg = 'Hello World!';

        $enc = $gcm->encrypt($msg);
        $dec = $gcm->decrypt($enc);

        $this->assertSame($dec, $msg);
    }

    public function testBadChecksum(): void
    {
        $rnd = random_bytes(32);

        $this->expectException(Exception::class);

        self::gcmConstrcutor()->decrypt($rnd);
    }

    public function testBadKey(): void
    {
        $this->expectException(Exception::class);

        (new AesGcm('short key'))->encrypt('Hello World!');
    }

    public function testSplitFunctionality1(): void
    {
        $gcm = self::gcmConstrcutor();

        $gcm->fallback = false;
        $enc = $gcm->encrypt('Hello World!');

        $gcm->fallback = true;
        $dec = $gcm->decrypt($enc);

        $this->assertEquals($dec, 'Hello World!');
    }

    public function testSplitFunctionality2(): void
    {
        $gcm = self::gcmConstrcutor();

        $gcm->fallback = true;
        $enc = $gcm->encrypt('Hello World!');

        $gcm->fallback = false;
        $dec = $gcm->decrypt($enc);

        $this->assertEquals($dec, 'Hello World!');
    }

    public function testKeyRotation(): void
    {
        $key1 = base64_encode(random_bytes(32));
        $key2 = base64_encode(random_bytes(32));
        $key3 = base64_encode(random_bytes(32));

        $gcm = new AesGcm($key1);
        $enc = $gcm->encrypt('Hello World!');

        $gcm = new AesGcm($key2);
        $gcm->rotated = [$key1];
        $dec = $gcm->decrypt($enc);
        $this->assertEquals('Hello World!', $dec);

        $gcm = new AesGcm($key3);
        $gcm->rotated = [$key1, $key2];
        $dec = $gcm->decrypt($enc);
        $this->assertEquals('Hello World!', $dec);
    }

    public function testAadAuthentication(): void
    {
        $gcm = self::gcmConstrcutor();

        $aad = 'authenticated meta data';
        $msg = 'secret message';

        $enc = $gcm->encrypt($msg, $aad);
        $dec = $gcm->decrypt($enc, $aad);

        $this->assertSame($msg, $dec);

        $this->expectException(Exception::class);
        $gcm->decrypt($enc, $aad . ' contamination');
    }
}
