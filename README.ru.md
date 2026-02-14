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
