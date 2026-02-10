<?php

declare(strict_types=1);

namespace Haikiri\SimplePhpTotp;

use PHPUnit\Framework\TestCase;

class TOTPTest extends TestCase
{
	private static $timestamp = 1234567890;
	private static $random_token = "2a182b53fc";
	private static $secret = "GJQTCOBSMI2TGZTD";
	private static $mocked_otp = "046352";

	public static function test_generateSecret()
	{
		# Real Generation.
		$random_token = substr(bin2hex(random_bytes(5)), 0, 10);
		$secret = TOTP::generateSecret($random_token);
		var_export([
			"random_token" => $random_token,
			"secret" => $secret,
			"mocked_otp" => TOTP::generate(self::$secret, self::$timestamp),
			"actual_otp" => TOTP::generate(self::$secret),
		]);

		self::assertSame(self::$secret, TOTP::generateSecret(self::$random_token));
	}

	public static function test_decodeSecret()
	{
		self::assertSame(self::$random_token, TOTP::decodeSecret(self::$secret));
	}

	public static function test_generateTotp()
	{
		self::assertEquals(self::$mocked_otp, TOTP::generate(self::$secret, self::$timestamp));

		$result = TOTP::generate(self::$secret);
		var_export(["actual" => $result]);
		self::assertGreaterThan(0, $result);
	}

}
