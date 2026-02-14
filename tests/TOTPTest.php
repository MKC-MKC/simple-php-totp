<?php

declare(strict_types=1);

namespace Haikiri\SimplePhpTotp\Tests;

use Exception;
use Haikiri\SimplePhpTotp\TOTP;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;

class TOTPTest extends TestCase
{
	const MOCK_TIME_SLICE = 1234567890;
	const MOCK_RANDOM_TOKEN = '2a182b53fc';
	const MOCK_SECRET = 'GJQTCOBSMI2TGZTD';
	const MOCK_OTP = '046352';

	/**
	 * Проверяем, что кодирование известного токена возвращает ожидаемый Base32-секрет.
	 * @return void
	 * @throws Exception
	 */
	public static function testGenerateSecretFromKnownToken()
	{
		self::assertSame(self::MOCK_SECRET, TOTP::generateSecret(self::MOCK_RANDOM_TOKEN));
	}

	/**
	 * Проверяем, что декодирование известного секрета возвращает исходный токен.
	 * @return void
	 */
	public static function testDecodeSecretFromKnownSecret()
	{
		self::assertSame(self::MOCK_RANDOM_TOKEN, TOTP::decodeSecret(self::MOCK_SECRET));
	}

	/**
	 * Проверяем, что генерация TOTP с известными мок-значениями возвращает ожидаемый токен.
	 * @return void
	 */
	public static function testGenerateTotpWithKnownMockValues()
	{
		self::assertSame(self::MOCK_OTP, TOTP::generate(self::MOCK_SECRET, self::MOCK_TIME_SLICE));
	}

	/**
	 * Проверяем, что авто-генерация без входных данных создает валидную строку Base32.
	 * @return void
	 * @throws Exception
	 */
	public static function testGenerateSecretWithoutInputCreatesValidBase32String()
	{
		$secret = TOTP::generateSecret();
		self::assertSame(16, strlen($secret));
		self::assertSame(1, preg_match('/^[A-Z2-7]+$/', $secret));
	}

	/**
	 * Проверяем устойчивость к нижнему регистру и разделителям.
	 * @return void
	 * @noinspection SpellCheckingInspection
	 */
	public static function testDecodeSecretSupportsLowercaseAndFormattingSeparators()
	{
		$formattedSecret = 'gjqt-cobs mi2t-gztd';
		self::assertSame(self::MOCK_RANDOM_TOKEN, TOTP::decodeSecret($formattedSecret));
	}

	/**
	 * Проверяем, что нулевые байты не теряются при кодировании/декодировании.
	 * @return void
	 * @throws Exception
	 */
	public static function testDecodeSecretKeepsNullBytes()
	{
		$binary = "A\0B\0C";
		$secret = TOTP::generateSecret($binary);
		self::assertSame($binary, TOTP::decodeSecret($secret));
	}

	/**
	 * Проверяем, что декодирование секрета с допустимым по RFC4648 работает правильно.
	 * @return void
	 * @noinspection SpellCheckingInspection
	 */
	public static function testDecodeSecretWithRfcPaddingVariant()
	{
		self::assertSame('foo', TOTP::decodeSecret('MZXW6==='));
	}

	/**
	 * Проверяем, что генерация TOTP с разной длиной OTP возвращает токен с правильным количеством цифр и нулевым заполнением.
	 * @return void
	 */
	public static function testGenerateTotpReturnsZeroPaddedTokenWithExpectedLength()
	{
		$token = TOTP::generate(self::MOCK_SECRET, self::MOCK_TIME_SLICE, 8);
		self::assertSame(8, strlen($token));
		self::assertSame(1, preg_match('/^\d{8}$/', $token));
	}

	/**
	 * Проводим тест нулевого среза времени, что он не ломается и возвращает ожидаемый токен.
	 * @return void
	 */
	public static function testGenerateTotpAcceptsZeroTimeSlice()
	{
		self::assertSame('981831', TOTP::generate(self::MOCK_SECRET, 0));
		self::assertSame('981831', TOTP::generate(self::MOCK_SECRET, '0'));
	}

	/**
	 * Проверяем, что генерация TOTP с недопустимыми аргументами выбрасывает исключение.
	 * @dataProvider invalidGenerateArgumentsProvider
	 * @param mixed $time
	 */
	public function testGenerateTotpRejectsInvalidArguments($time, int $otpLength)
	{
		$this->expectException(InvalidArgumentException::class);
		TOTP::generate(self::MOCK_SECRET, $time, $otpLength);
	}

	/**
	 * Провайдер данных с различными недопустимыми аргументами для генерации TOTP.
	 * @return array
	 */
	public static function invalidGenerateArgumentsProvider(): array
	{
		return [
			'negative time' => [-1, 6],
			'float time' => [1.5, 6],
			'non numeric string time' => ['abc', 6],
			'otp length too small' => [self::MOCK_TIME_SLICE, 0],
			'otp length too large' => [self::MOCK_TIME_SLICE, 10],
		];
	}

	/**
	 * Проверяем, что декодирование недопустимых строк выбрасывает исключение.
	 * @dataProvider invalidSecretProvider
	 * @param string $secret
	 * @return void
	 */
	public function testDecodeSecretRejectsInvalidSecrets(string $secret)
	{
		$this->expectException(InvalidArgumentException::class);
		TOTP::decodeSecret($secret);
	}

	/**
	 * Провайдер данных с различными недопустимыми строками для декодирования.
	 * @return array[]
	 * @noinspection SpellCheckingInspection
	 */
	public static function invalidSecretProvider(): array
	{
		return [
			'empty string' => [''],
			'invalid alphabet symbol' => ['GJQTCOBSMI2TGZT1'],
			'padding in the middle' => ['GJQT=COBSMI2TGZTD'],
			'invalid padding count' => ['MY======='],
			'invalid unpadded length remainder' => ['ABC'],
		];
	}

	/**
	 * Проверяем, что ссылка формируется в корректном формате.
	 * @return void
	 * @noinspection SpellCheckingInspection
	 */
	public static function testGetTotpUrlBuildsExpectedOtpauthLink()
	{
		$s = self::MOCK_SECRET;
		$url = TOTP::getTotpUrl($s, 'user@example.com', 'My Service');
		self::assertSame("otpauth://totp/My%20Service:user%40example.com?secret=$s&issuer=My%20Service", $url);
	}

	/**
	 * Проверяем нормализацию секрета.
	 * @return void
	 * @noinspection SpellCheckingInspection
	 */
	public static function testGetTotpUrlNormalizesSecret()
	{
		$url = TOTP::getTotpUrl(' gjqt-cobs mi2t-gztd ', 'client-1', 'ACME');
		self::assertStringContainsString('secret=' . self::MOCK_SECRET, $url);
	}

	/**
	 * Проверяем, что генерация ссылки с недопустимыми аргументами выбрасывает исключение.
	 * @dataProvider invalidTotpUrlArgumentsProvider
	 * @return void
	 */
	public function testGetTotpUrlRejectsInvalidArguments(string $secret, string $username, string $issuer)
	{
		$this->expectException(InvalidArgumentException::class);
		TOTP::getTotpUrl($secret, $username, $issuer);
	}

	/**
	 * Провайдер невалидных аргументов для формирования ссылки.
	 * @return array
	 * @noinspection SpellCheckingInspection
	 */
	public static function invalidTotpUrlArgumentsProvider(): array
	{
		return [
			'empty secret' => ['', 'user', 'issuer'],
			'invalid secret chars' => ['ABCD1', 'user', 'issuer'],
			'empty username' => [self::MOCK_SECRET, '   ', 'issuer'],
			'empty issuer' => [self::MOCK_SECRET, 'user', '   '],
		];
	}
}
