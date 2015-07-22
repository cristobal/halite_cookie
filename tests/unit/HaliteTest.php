<?php
class HaliteTest extends PHPUnit_Framework_TestCase
{
    public function testCrypto()
    {
        try {
            $halite = new \ParagonIE\Halite\Cookie(
                new \ParagonIE\Halite\Key(
                    \str_repeat('A', \Sodium::CRYPTO_SECRETBOX_KEYBYTES)
                )
            );
            $this->assertFalse(true);
        } catch (Exception $e) {
            $halite = new \ParagonIE\Halite\Cookie(
                new \ParagonIE\Halite\Key(
                    \Sodium::randombytes_buf(
                        \Sodium::CRYPTO_SECRETBOX_KEYBYTES
                    )
                )
            );
        }
        $msg = 'We attack at dawn.';
        
        $encrypted = $halite->encrypt($msg);
        $this->assertNotEmpty($encrypted);
        $this->assertEquals(\mb_strlen($encrypted, '8bit'), 80);
        $decrypted = $halite->decrypt($encrypted);
        $this->assertEquals($decrypted, $msg);
    }
    
    public function testPasswordDerivation()
    {
        $key = new \ParagonIE\Halite\Key;
        try {
            $key->derive(
                'co-wrecked hoarse assault maple',
                \str_repeat('A', \Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES)
            );
        } catch (Exception $e) {
            $key->derive(
                'co-wrecked hoarse assault maple',
                "\xF1\x02\xE3\x14\xD5\x26\xC7\x38\xB9\x4A\xAB\x5C\x9D\x6E\x7F\x80".
                "\xF0\xD1\xC2\xB3\xE4\xA5\x96\x87\x78\x69\x5A\x4B\x3C\x2D\x1E\x0F"
            );
        }
        $this->assertEquals(
            \mb_strlen($key->getKey(), '8bit'),
            \Sodium::CRYPTO_SECRETBOX_KEYBYTES
        );
    }
}
