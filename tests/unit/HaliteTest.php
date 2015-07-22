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
}
