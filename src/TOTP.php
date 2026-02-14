<?php

declare(strict_types=1);

namespace Haikiri\SimplePhpTotp;

use Exception;
use InvalidArgumentException;

class TOTP
{
	/**
	 * Набор символов RFC4648 base32-алфавита.
	 * @noinspection SpellCheckingInspection
	 */
	const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	# Маппинг для быстрого декодирования символов base32 в их числовые значения.
	private static $base32Map = null;

	/**
	 * Строит таблицу соответствия base32-символа к числу.
	 * @return array<string, int>
	 */
	private static function getBase32Map(): array
	{
		if (self::$base32Map !== null) return self::$base32Map;

		$map = [];
		$alphabetLength = strlen(self::BASE32_ALPHABET);

		for ($i = 0; $i < $alphabetLength; $i++) {
			$map[self::BASE32_ALPHABET[$i]] = $i;
		}

		self::$base32Map = $map;
		return self::$base32Map;
	}

	/**
	 * Метод создания секретного кода для TOTP приложения.
	 * @param string $string
	 * @return string
	 * @throws Exception
	 */
	public static function generateSecret(string $string = ''): string
	{
		if (empty($string)) $string = substr(bin2hex(random_bytes(5)), 0, 10);

		$remainderCount = 0;
		$remainder = 0;
		$result = '';

		for ($i = 0; $i < strlen($string); $i++) {
			$remainder = ($remainder << 8) | ord($string[$i]);
			$remainderCount += 8;

			# Извлекаем из буфера по 5 бит и конвертируем в base32 символы.
			while ($remainderCount >= 5) {
				$remainderCount -= 5;
				$c = ($remainder >> $remainderCount) & 0x1F;
				$result .= self::BASE32_ALPHABET[$c];
			}

			# Держим в буфере только битовые хвосты, чтобы не раздувать число.
			$remainder &= (1 << $remainderCount) - 1;
		}

		# Добиваем оставшиеся биты нулями справа до 5 бит.
		if ($remainderCount > 0) {
			$index = ($remainder << (5 - $remainderCount)) & 0x1F;
			$result .= self::BASE32_ALPHABET[$index];
		}

		return $result;
	}

	/**
	 * Метод расшифровки секретного кода.
	 * @param string $string
	 * @return string
	 */
	public static function decodeSecret(string $string): string
	{
		$string = trim($string);
		if (empty($string)) throw new InvalidArgumentException('Secret string cannot be empty');

		# Учитываем пробелы и дефисы от клиента.
		$input = str_replace([' ', '-'], '', $string);
		$input = strtoupper($input);

		# Допускаем символ '=' только как хвостовой base32-padding.
		$firstPaddingPos = strpos($input, '=');
		$paddingLength = 0;

		if ($firstPaddingPos !== false) {
			$paddingLength = strlen($input) - $firstPaddingPos;
			$paddingTail = substr($input, $firstPaddingPos);

			# Проверяем, что все символы после первого '=' - это '='.
			if ($paddingTail !== str_repeat('=', $paddingLength)) {
				throw new InvalidArgumentException('Padding is allowed only at the end');
			}

			# Для base32 длина должна быть кратна 8.
			if ((strlen($input) % 8) !== 0) {
				throw new InvalidArgumentException('Invalid padded secret length');
			}

			# Допустимые хвосты по RFC4648: 6, 4, 3, 1.
			if (!in_array($paddingLength, [6, 4, 3, 1], true)) {
				throw new InvalidArgumentException('Invalid symbols count');
			}

			$input = substr($input, 0, $firstPaddingPos);
		}

		# После удаления хвостов строка не должна быть пустой.
		if ($input === '') throw new InvalidArgumentException('Secret string cannot be empty');

		# Проверяем, что в строке только допустимые символы base32 (без '=').
		if (!preg_match('/^[A-Z2-7]+$/', $input)) {
			throw new InvalidArgumentException('Invalid secret symbol');
		}

		# Для строк без хвостов проверяем, что длина соответствует допустимым остаткам от деления на 8.
		if ($paddingLength === 0) {
			$remainder = strlen($input) % 8;
			if (!in_array($remainder, [0, 2, 4, 5, 7], true)) {
				throw new InvalidArgumentException('Invalid symbols count');
			}
		}

		# Переводим base32 обратно в байты: собираем по 5 бит и выгружаем блоками по 8.
		$map = self::getBase32Map();
		$bitBuffer = 0;
		$bitCount = 0;
		$decoded = '';
		$inputLength = strlen($input);

		for ($i = 0; $i < $inputLength; $i++) {
			$value = $map[$input[$i]];
			$bitBuffer = ($bitBuffer << 5) | $value;
			$bitCount += 5;

			while ($bitCount >= 8) {
				$bitCount -= 8;
				$decoded .= chr(($bitBuffer >> $bitCount) & 0xFF);
			}

			# Снова оставляем только хвостовые биты.
			$bitBuffer &= (1 << $bitCount) - 1;
		}

		# Остаточные биты должны быть нулями.
		if ($bitCount > 0 && $bitBuffer !== 0) {
			throw new InvalidArgumentException('Invalid trailing bits in secret');
		}

		return $decoded;
	}

	/**
	 * Метод выполняет генерацию TOTP-кода.
	 * @param string $secret
	 * @param mixed $time
	 * @param int $otp_length
	 * @return string
	 */
	public static function generate(string $secret, $time = null, int $otp_length = 6): string
	{
		if (trim($secret) === '') throw new InvalidArgumentException('Secret string cannot be empty');

		# Ограничиваем длину OTP от 1 до 9.
		if ($otp_length < 1 || $otp_length > 9) {
			throw new InvalidArgumentException('OTP length must be between 1 and 9');
		}

		# Обработка времени.
		if ($time === null) {
			$timeValue = intdiv(time(), 30);
		} elseif (is_int($time)) {
			$timeValue = $time;
		} elseif (is_string($time) && preg_match('/^-?\d+$/', $time)) {
			$timeValue = (int)$time;
		} else {
			throw new InvalidArgumentException('Time value must be an integer or null');
		}

		# Если время отрицательное - это ошибка, так как OTP не может работать в прошедшем времени.
		if ($timeValue < 0) throw new InvalidArgumentException('Time must be greater than or equal to 0');

		# Упаковываем время в `unsigned long` - `SPACE-padded string`.
		$timeBytes = pack('N2', 0, $timeValue);

		# Генерируем Хеш из base32-секрета.
		$hash = hash_hmac('sha1', $timeBytes, self::decodeSecret($secret), true);

		# Точка смещения по младшим 4 битам последнего байта.
		$offset = ord($hash[19]) & 0x0F;
		$selectedBytes = substr($hash, $offset, 4);
		$binaryParts = unpack('N', $selectedBytes);
		$binary = $binaryParts[1] & 0x7FFFFFFF;

		# Дополняем токен нулями слева до нужной длины.
		return str_pad((string)($binary % self::pow($otp_length)), $otp_length, '0', STR_PAD_LEFT);
	}

	/**
	 * Генерируем ссылку для TOTP-приложений.
	 * @param string $secret Исходный OTP секрет в формате Base32.
	 * @param string $username Идентификатор клиента в системе.
	 * @param string $issuer Название организации/проекта.
	 * @return string
	 * @noinspection SpellCheckingInspection
	 */
	public static function getTotpUrl(string $secret, string $username, string $issuer): string
	{
		# Нормализуем и валидируем обязательные поля.
		$normalizedSecret = strtoupper(str_replace([' ', '-'], '', trim($secret)));
		$normalizedUsername = trim($username);
		$normalizedIssuer = trim($issuer);

		if ($normalizedSecret === '') throw new InvalidArgumentException('Secret string cannot be empty');
		if ($normalizedUsername === '') throw new InvalidArgumentException('Username cannot be empty');
		if ($normalizedIssuer === '') throw new InvalidArgumentException('Issuer cannot be empty');

		# Проверяем, что переданный секрет действительно корректный base32.
		self::decodeSecret($normalizedSecret);

		# Формируем label вида `issuer:username`.
		$encodedIssuer = rawurlencode($normalizedIssuer);
		$encodedUsername = rawurlencode($normalizedUsername);
		$label = "$encodedIssuer:$encodedUsername";

		return 'otpauth://totp/' . $label . '?secret=' . rawurlencode($normalizedSecret) . '&issuer=' . $encodedIssuer;
	}

	/**
	 * Избегаем float погрешностей при больших степенях.
	 * @param int $power
	 * @return int
	 */
	private static function pow(int $power): int
	{
		$value = 1;
		for ($i = 0; $i < $power; $i++) $value *= 10;
		return $value;
	}
}
