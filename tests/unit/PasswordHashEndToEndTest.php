<?php

namespace Openwall\PHPass\Tests;

use PasswordHash;
use PHPUnit\Framework\TestCase;

/**
 * Basic end-to-end tests for the PasswordHash class.
 *
 * @covers \PasswordHash
 */
final class PasswordHashEndToEndTest extends TestCase {

	/**
	 * Test using the stronger but system-specific hashes, with a possible fallback to
	 * the weaker portable hashes.
	 *
	 * @dataProvider dataSetsSuccess
	 *
	 * @param string $input The text to hash and compare with.
	 *
	 * @return void
	 */
	public function testStrongerSystemSpecificHashSuccess($input) {
		$t_hasher = new PasswordHash(8, FALSE);
		$hash = $t_hasher->HashPassword($input);

		$this->assertTrue($t_hasher->CheckPassword($input, $hash));
	}

	/**
	 * Test using the stronger but system-specific hashes, with a possible fallback to
	 * the weaker portable hashes.
	 *
	 * @dataProvider dataSetsFail
	 *
	 * @param string $input   The text to hash.
	 * @param string $compare The text to compare the hash with.
	 *
	 * @return void
	 */
	public function testStrongerSystemSpecificHashFail($input, $compare) {
		$t_hasher = new PasswordHash(8, FALSE);
		$hash = $t_hasher->HashPassword($input);

		$this->assertFalse($t_hasher->CheckPassword($compare, $hash));
	}

	/**
	 * Test using the weaker portable hashes.
	 *
	 * @dataProvider dataSetsSuccess
	 *
	 * @param string $input The text to hash and compare with.
	 *
	 * @return void
	 */
	public function testWeakerPortableHashSuccess($input) {
		# Force the use of weaker portable hashes.
		$t_hasher = new PasswordHash(8, TRUE);
		$hash = $t_hasher->HashPassword($input);

		$this->assertTrue($t_hasher->CheckPassword($input, $hash));
	}

	/**
	 * Test using the weaker portable hashes.
	 *
	 * @dataProvider dataSetsFail
	 *
	 * @param string $input   The text to hash.
	 * @param string $compare The text to compare the hash with.
	 *
	 * @return void
	 */
	public function testWeakerPortableHashFail($input, $compare) {
		# Force the use of weaker portable hashes.
		$t_hasher = new PasswordHash(8, TRUE);
		$hash = $t_hasher->HashPassword($input);

		$this->assertFalse($t_hasher->CheckPassword($compare, $hash));
	}

	/**
	 * Data provider.
	 *
	 * @return array
	 */
	public static function dataSetsSuccess() {
		$data = self::dataSets();
		foreach ($data as $key => $value) {
			// The `compare` parameter is only needed for the "fail" tests.
			unset($data[$key]['compare']);
		}

		return $data;
	}

	/**
	 * Data provider.
	 *
	 * @return array
	 */
	public static function dataSetsFail() {
		return self::dataSets();
	}

	/**
	 * Data provider helper.
	 *
	 * @return array
	 */
	public static function dataSets() {
		return array(
			'initial test case' => array(
				'input'   => 'test12345',
				'compare' => 'test12346',
			),
		);
	}

	/**
	 * Test the generated hash is correctly calculated using the weaker portable hashes.
	 *
	 * @dataProvider dataGeneratedHashSuccess
	 *
	 * @param string $expected_hash The expected password hash output.
	 * @param string $input         The text to hash and compare with.
	 *
	 * @return void
	 */
	public function testGeneratedHashSuccess($expected_hash, $input) {
		$t_hasher = new PasswordHash(8, TRUE);

		$this->assertTrue($t_hasher->CheckPassword($input, $expected_hash));
	}

	/**
	 * Data provider.
	 *
	 * @return array
	 */
	public static function dataGeneratedHashSuccess() {
		$data = self::dataGeneratedHash();
		foreach ($data as $key => $value) {
			// The `compare` parameter is only needed for the "fail" tests.
			unset($data[$key]['compare']);
		}

		return $data;
	}

	/**
	 * Test the generated hash is correctly calculated using the weaker portable hashes.
	 *
	 * @dataProvider dataGeneratedHashFail
	 *
	 * @param string $expected_hash The expected password hash output.
	 * @param string $input         Unused.
	 * @param string $compare       The text to compare the hash with.
	 *
	 * @return void
	 */
	public function testGeneratedHashFail($expected_hash, $input, $compare) {
		$t_hasher = new PasswordHash(8, TRUE);

		$this->assertFalse($t_hasher->CheckPassword($compare, $expected_hash));
	}

	/**
	 * Data provider.
	 *
	 * @return array
	 */
	public static function dataGeneratedHashFail() {
		return self::dataGeneratedHash();
	}

	/**
	 * Data provider helper.
	 *
	 * @return array
	 */
	public static function dataGeneratedHash() {
		return array(
			'initial test case' => array(
				/*
				 * A correct portable hash for 'test12345'.
				 * Please note the use of single quotes to ensure that the dollar signs will
				 * be interpreted literally.  Of course, a real application making use of the
				 * framework won't store password hashes within a PHP source file anyway.
				 * We only do this for testing.
				 */
				'expected_hash' => '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0',
				'input'         => 'test12345',
				'compare'       => 'test12346',
			),
		);
	}
}
