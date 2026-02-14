# simple-php-totp

Language: [English](README.md) | **Русский**

Максимально лёгкая и ванильная PHP библиотека для генерации TOTP (2FA) кодов.

## Совместимость

- PHP 7+ && PHP 8+
- Тесты: `phpunit/phpunit` (`^9.6 || ^8.5 || ^6.5`)

## Установка

```bash
composer require haikiri/simple-php-totp
```

## Пример использования

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use Haikiri\SimplePhpTotp\TOTP;

# Генерация секрета для хранения в БД.
$secret = TOTP::generateSecret();

# Генерация 6-значного OTP-кода на основе секрета.
$code = TOTP::generate($secret);

echo $secret . PHP_EOL; # Секрет для пользователя. (нужно сохранить в БД пользователя)
echo $code . PHP_EOL; # TOTP-код, с которым мы должны сравнить код переданный пользователем из 2FA-приложения.
```

## Получение OTPAuth URL

```php
<?php

use Haikiri\SimplePhpTotp\TOTP;

$url = TOTP::getTotpUrl(
    'GJQTCOBSMI2TGZTD', # OTP-секрет (Base32)
    'user@example.com', # Username / идентификатор клиента
    'My Service' # Issuer / название организации
);

echo $url . PHP_EOL; # otpauth://totp/My%20Service:user%40example.com?secret=GJQTCOBSMI2TGZTD&issuer=My%20Service
```
