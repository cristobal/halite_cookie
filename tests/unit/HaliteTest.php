<?php
class HaliteTest extends PHPUnit_Framework_TestCase
{
    public function testCrypto()
    {
        $halite = new \ParagonIE\Halite\Cookie(
            new \ParagonIE\Halite\Key(
                \str_repeat('A', \Sodium::CRYPTO_SECRETBOX_KEYBYTES)
            )
        );
        $msg = 'We attack at dawn.';
        
        $encrypted = $halite->encrypt($msg);
        $this->assertNotEmpty($encrypted);
        $decrypted = $halite->decrypt($msg);
        $this->assertEquals($decrypted, $msg);
    }
}
