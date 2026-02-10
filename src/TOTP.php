<?php

declare(strict_types=1);

namespace Haikiri\SimplePhpTotp;

use Exception;
use InvalidArgumentException;

class TOTP
{
	/**
	 * Набор символов.
	 * @noinspection SpellCheckingInspection
	 */
	private static $charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	/**
	 * Метод создания секретного кода для TOTP приложения.
	 * @param string|null $string
	 * @return string
	 * @throws Exception
	 */
	public static function generateSecret(string $string = null): string
	{
		if (empty($string)) $string = substr(bin2hex(random_bytes(5)), 0, 10);

		$remainderSize = 0;
		$remainder = 0;
		$result = '';

		for ($i = 0; $i < strlen($string); $i++) {
			$remainder = ($remainder << 8) | ord($string[$i]);
			$remainderSize += 8;

			while ($remainderSize > 4) {
				$remainderSize -= 5;
				$c = $remainder & (31 << $remainderSize);
				$c >>= $remainderSize;
				$result .= self::$charset[$c];
			}
		}

		if ($remainderSize > 0) {
			$remainder <<= (5 - $remainderSize);
			$result .= self::$charset[$remainder];
		}

		return $result;
	}

	/**
	 * Метод расшифровки секретного кода.
	 * @param string|null $string
	 * @return string
	 */
	public static function decodeSecret(string $string): string
	{
		if (empty($string)) throw new InvalidArgumentException('Secret string cannot be empty');

		if (!in_array(substr_count($string, '='), [6, 4, 3, 1, 0])) {
			throw new InvalidArgumentException('Invalid symbols count');
		}

		$input = str_replace('=', '', $string);
		$input = str_split($input);
		$binaryString = '';

		for ($i = 0, $count = count($input); $i < $count; $i += 8) {
			$x = '';

			if ($i + 7 >= $count) {
				$input = array_merge($input, array_fill(0, 8 - ($count % 8), 0));
			}

			foreach (array_slice($input, $i, 8) as $item) {
				$pos = strrpos(self::$charset, $item);
				if ($pos === false) throw new InvalidArgumentException('Invalid secret symbol');
				$x .= str_pad(base_convert((string)$pos, 10, 2), 5, '0', STR_PAD_LEFT);
			}

			foreach (str_split($x, 8) as $bit) {
				if (strlen($bit) >= 8) {
					$y = chr((int)base_convert($bit, 2, 10));
					if ($y || ord($y) == 48) $binaryString .= $y;
				}
			}
		}

		return $binaryString;
	}

	/**
	 * Метод выполняет генерацию TOTP-кода.
	 * @param string|null $secret
	 * @param int|null $time
	 * @param int $otp_length
	 * @return string
	 */
	public static function generate(string $secret, int $time = null, int $otp_length = 6): string
	{
		if (empty($secret)) throw new InvalidArgumentException('Secret string cannot be empty');

		# Обработка времени.
		$timeValue = empty($time) ? (int)floor(time() / 30) : $time;
		$time = pack('N2', 0, $timeValue);

		# Генерируем Хеш и точку смещения.
		$hash = hash_hmac('sha1', $time, self::decodeSecret($secret), true);

		# Точка смещения из последнего бита хеша.
		$offset = ord($hash[strlen($hash) - 1]) & 0x0F;

		# Извлекаем 4 байта из хеша, начиная со смещения.
		$binary = unpack('N', $hash, $offset)[1] & 0x7FFFFFFF;

		# Дополняем токен нулями слева до нужной длины.
		return str_pad((string)($binary % pow(10, $otp_length)), $otp_length, '0', STR_PAD_LEFT);
	}
}
