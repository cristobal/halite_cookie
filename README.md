# Halite 

[![Build Status](https://travis-ci.org/paragonie/halite_cookie.svg?branch=master)](https://travis-ci.org/paragonie/halite_cookie)

Encrypted Cookies in PHP with [Libsodium](https://github.com/jedisct1/libsodium-php).

An open source project by [Paragon Initiative Enterprises](https://paragonie.com).
To learn more about safely implementing cryptography in your application, see our
blog post titled [Using Encryption and Authentication Properly (in PHP)](https://paragonie.com/blog/2015/05/using-encryption-and-authentication-correctly).

## Installing

```sh
sudo apt-get update
sudo apt-get install make build-essential automake php5-dev php-pear
git clone git://github.com/jedisct1/libsodium.git
cd libsodium
git checkout 1.0.3
./autogen.sh
./configure && make check
sudo make install
cd ..
sudo pecl install libsodium-beta
sudo php5enmod libsodium
```

## Usage Example

### Key Generation

First, you want to generate an encryption key.

```php
$key = new \ParagonIE\Halite\Key;
$key->generate();
echo \Sodium::bin2hex($key->getKey());
```
#### (Optional) Password-Based Encryption Keys

First, store a sufficiently large random value. Then use it in conjunction with
your password to derive a key.

```php
$key = new \ParagonIE\Halite\Key;
$key->derive(
    // Password:
    'correct horse battery staple is now very shabby',
    // Salt:
    YOUR_STATIC_HALITE_PW_SALT
);
```

### Encrypted Cookie Storage

Next, save your key somewhere you can simply do the following:

```php
$key = new \ParagonIE\Halite\Key(\Sodium::hex2bin(SAVED_ENCRYPTION_KEY));
$cookie = new \ParagonIE\Halite\Cookie($key);
$cookie->store($key, $value);
```

### Retrieving Values from Encrypted Cookies

Next, save your key somewhere you can simply do the following:

```php
$value = $cookie->fetch($key);
```