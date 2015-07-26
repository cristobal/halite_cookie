<?php
namespace ParagonIE\Halite;

final class Key
{
    private $secretbox_key;
    const MIN_COMPRESSED_KEYSIZE = 32; // 75% of CRYPTO_SECRETBOX_KEYBYTES + 8 overhead
    const MIN_COMPRESSED_SALTSIZE = 32; // 75% of CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES + 8 overhead
    const BITMIN = 112;
    const BITMAX = 144;
    
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
            $this->secretbox_key = \Sodium\randombytes_buf(
                \Sodium\CRYPTO_SECRETBOX_KEYBYTES
            );
        } while ($this->testKeyEntropy($this->secretbox_key, true));
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
    public function derive($password, $salt, $len = \Sodium\CRYPTO_SECRETBOX_KEYBYTES)
    {
        $this->testSaltEntropy($salt);
        
        $this->secretbox_key = \Sodium::crypto_pwhash_scryptsalsa208sha256(
            $len,
            $password, 
            $salt,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_OPSLIMIT_INTERACTIVE,
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_MEMLIMIT_INTERACTIVE
        );
        
        \Sodium::sodium_memzero($password);
        return $this;
    }
    
    /**
     * Get a new salt for use wih scrypt for key derivation
     * 
     * @return string
     */
    public static function newPasswordSalt()
    {
        return \Sodium\randombytes_buf(
            \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES
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
     * Count the number of bits in a string
     * 
     * @param string $str
     * @return array
     */
    private function countBits($str)
    {
        $bits = [0,0];
        $len = \mb_strlen($str, '8bit');
        for ($i = 0; $i < $len; ++$i) {
            $c = \ord($str[$i]);
            for ($j = 0; $j < 8; ++$j) {
                if (($c & 0x01) === 0) {
                    ++$bits[0];
                } else {
                    ++$bits[1];
                }
                $c >>= 1;
            }
        }
        return $bits;
    }
    
    /**
     * Test that a given key is the proper length and has sufficient entropy
     * 
     * @param string $key Should be a 32-byte random key
     * @param boolean $dont_throw Should we just return false instead of throwing an exception?
     * @return boolean
     * @throws \Exception
     */
    public function testKeyEntropy($key, $dont_throw = false)
    {
        if (\mb_strlen($key, '8bit') !== \Sodium\CRYPTO_SECRETBOX_KEYBYTES) {
            if ($dont_throw) {
                return false;
            }
            throw new \Exception("You must use an encryption key. A password will not work. Use generate() to create a proper encryption key.");
        }
        $compressed = \gzcompress($key, 1);
        if (\mb_strlen($compressed, '8bit') < self::MIN_COMPRESSED_KEYSIZE) {
            if ($dont_throw) {
                return false;
            }
            throw new \Exception("You must use a random salt. A password will not work.");
        }
        
        $bits = $this->countBits($key);
        if ($bits[0] < self::BITMIN || $bits[1] < self::BITMIN || $bits[0] > self::BITMAX || $bits[1] > self::BITMAX) {
            if ($dont_throw) {
                return false;
            }
            throw new \Exception("You must use an encryption key. A password will not work. Use generate() to create a proper encryption key.");
        }
    }
    
    /**
     * Test that a given salt is the proper length and has sufficient entropy
     * 
     * @param string $salt Should be a 32-byte random key
     * @param boolean $dont_throw Should we just return false instead of throwing an exception?
     * @return boolean
     * @throws \Exception
     */
    public function testSaltEntropy($salt, $dont_throw = false)
    {
        if (mb_strlen($salt, '8bit') !== \Sodium\CRYPTO_PWHASH_SCRYPTSALSA208SHA256_SALTBYTES) {
            if ($dont_throw) {
                return false;
            }
            throw new \Exception("You must use a random salt. A password will not work.");
        }
        $compressed = \gzcompress($salt, 1);
        if (mb_strlen($compressed, '8bit') < self::MIN_COMPRESSED_SALTSIZE) {
            if ($dont_throw) {
                return false;
            }
            throw new \Exception("You must use a random salt. A password will not work.");
        }
        
        $bits = $this->countBits($salt);
        
        if ($bits[0] < self::BITMIN || $bits[1] < self::BITMIN || $bits[0] > self::BITMAX || $bits[1] > self::BITMAX) {
            if ($dont_throw) {
                return false;
            }
            throw new \Exception("You must use a random salt. A password will not work.");
        }
    }
}
