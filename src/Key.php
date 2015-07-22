<?php
namespace ParagonIE\Halite;

final class Key
{
    private $secretbox_key;
    const MIN_COMPRESSED_KEYSIZE = 24; // 75% of CRYPTO_SECRETBOX_KEYBYTES
    
    public function __construct($key = null)
    {
        if ($key !== null) {
            $this->testKeyEntropy($key);
            $this->secretbox_key = $key;
        }
    }
    
    /**
     * Generate a new random key, store in $this->secretbox_key
     * 
     * @return Key
     */
    public function generate()
    {
        do {
            $this->secretbox_key = \Sodium::randombytes_buf(
                \Sodium::CRYPTO_SECRETBOX_KEYBYTES
            );
        } while ($this->testKeyEntropy($key, true));
        return $this;
    }
    
    /**
     * Derive an encryption key from a password and a salt
     * 
     * @param string $password
     * @param string $salt
     * @param int $len (how long should the key be?)
     * 
     * @return Key
     */
    public function derive($password, $salt, $len = \Sodium::CRYPTO_SECRETBOX_KEYBYTES)
    {
        if (\mb_strlen($salt, '8bit') !== \Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES) {
            throw new \Exception(
                'Salt must be '.\Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES.' bytes long'
            );
        }
        
        $this->secretbox_key = \Sodium::crypto_pwhash_scryptsalsa208sha256(
            $len,
            $password, 
            $salt,
            \Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            \Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
        );
        
        \Sodium::sodium_memzero($password);
        return $this;
    }
    
    /**
     * Get a new salt for use with 
     * 
     * @return string
     */
    public static function newPasswordSalt()
    {
        return \Sodium::randombytes_buf(
            \Sodium::CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES
        );
    }
    
    /**
     * Get the secretbox encryption key
     * 
     * @return string
     */
    public function getKey()
    {
        if ($this->secretbox_key === null) {
            throw new \Exception('No encryption key was set!');
        }
        return $this->secretbox_key;
    }
    
    /**
     * Test that a given key is the proper length and has sufficient entropy
     * 
     * @param string $key Should be a 32-byte random key
     * @return boolean
     * @throws \Exception
     */
    private function testKeyEntropy($key, $dont_throw = false)
    {
        if (mb_strlen($key, '8bit') !== \Sodium::CRYPTO_SECRETBOX_KEYBYTES) {
            if ($dont_throw) {
                return false;
            }
            throw new \Exception("You must use an encryption key. A password will not work. Use derive() instead.");
        }
        $compressed = \gzcompress($key, 9);
        if (mb_strlen($key, '8bit') < self::MIN_COMPRESSED_KEYSIZE) {
            if ($dont_throw) {
                return false;
            }
            throw new \Exception("You must use an encryption key. A password will not work. Use derive() instead.");
        }
        return true;
    }
}
