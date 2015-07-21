<?php
namespace ParagonIE\Halite;

final class Key
{
    private $secretbox_key;
    
    public function __construct($key = null)
    {
        $this->secretbox_key = $key;
    }
    
    /**
     * Generate a new random key, store in $this->secretbox_key
     * 
     * @return Key
     */
    public function generate()
    {
        $this->secretbox_key = \Sodium::randombytes_buf(
            \Sodium::CRYPTO_SECRETBOX_KEYBYTES
        );
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
}
