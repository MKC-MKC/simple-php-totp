# simple-php-totp

Language: **English** | [Русский](README.ru_RU.md)

A lightweight and vanilla PHP library for generating TOTP (2FA) codes.

## Compatibility

- PHP 7+ && PHP 8+
- Tests: `phpunit/phpunit` (`^9.6 || ^8.5 || ^6.5`)

## Installation

```bash
composer require haikiri/simple-php-totp
```

## Usage example

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Haikiri\SimplePhpTotp\TOTP;

# Generate a secret for storing in the DB.
$secret = TOTP::generateSecret();

# Generate a 6-digit OTP code based on the secret.
$code = TOTP::generate($secret);

echo $secret . PHP_EOL; # Secret for the user. (needs be stored in the user's DB)
echo $code . PHP_EOL; # TOTP-code with which we should compare the code provided by the user from the 2FA-app.
```

## Get OTPAuth URL

```php
<?php

use Haikiri\SimplePhpTotp\TOTP;

$url = TOTP::getTotpUrl(
    'GJQTCOBSMI2TGZTD', # OTP-secret (Base32)
    'user@example.com', # Username / client identifier
    'My Service' # Issuer / organization name
);

echo $url . PHP_EOL; # otpauth://totp/My%20Service:user%40example.com?secret=GJQTCOBSMI2TGZTD&issuer=My%20Service
```
