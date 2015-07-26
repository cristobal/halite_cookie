<?php
namespace ParagonIE\Halite;

class Halite
{
    protected $key;
    
    public function __construct(Key $key)
    {
        $key->testKeyEntropy($key->getKey());
        $this->key = $key;
    }
    
    /**
     * Encrypt a string
     * 
     * @param string $plaintext
     * @return string
     */
    public function encrypt($plaintext)
    {
        $nonce = \Sodium\randombytes_buf(
            \Sodium::CRYPTO_SECRETBOX_NONCEBYTES
        );
        $encrypted = \base64_encode(
            $nonce.
            \Sodium\crypto_secretbox(
                \json_encode($plaintext),
                $nonce,
                $this->key->getKey()
            )
        );
        \Sodium\memzero($plaintext);
        return $encrypted;
    }
    
    /**
     * Decrypt a string
     * 
     * @param string $encoded
     * @return string
     */
    public function decrypt($encoded)
    {
        $decoded = \base64_decode($encoded);
        \Sodium\memzero($encoded);
        
        $nonce = \mb_substr(
            $decoded,
            0,
            \Sodium\CRYPTO_SECRETBOX_NONCEBYTES,
            '8bit'
        );
        $ciphertext = \mb_substr(
            $decoded,
            \Sodium\CRYPTO_SECRETBOX_NONCEBYTES,
            null,
            '8bit'
        );
        
        $decrypted = \Sodium\crypto_secretbox_open(
            $ciphertext,
            $nonce,
            $this->key->getKey()
        );
        \Sodium\memzero($decoded);
        \Sodium\memzero($nonce);
        \Sodium\memzero($ciphertext);
        return \json_decode($decrypted, true);
    }   
}
