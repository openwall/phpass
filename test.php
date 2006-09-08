<?php
#
# This is a test program for the portable PHP password hashing framework.
#
# Written by Solar Designer and placed in the public domain.
# See PasswordHash.php for more information.
#

require "PasswordHash.php";

# Try to use stronger but system-specific hashes, with a possible fallback to
# the weaker portable hashes.
$t_hasher = new PasswordHash(8, FALSE);

$pw1 = "test12345";
$pw2 = "test12346";
$hash = $t_hasher->HashPassword($pw1);

print $hash . "\n";
print $t_hasher->CheckPassword($pw1, $hash) . "\n"; # prints 1
print $t_hasher->CheckPassword($pw2, $hash) . "\n"; # prints 0 or nothing

unset($t_hasher);

# Force the use of weaker portable hashes.
$t_hasher = new PasswordHash(8, TRUE);

$hash = $t_hasher->HashPassword($pw1);

print $hash . "\n";
print $t_hasher->CheckPassword($pw1, $hash) . "\n"; # prints 1
print $t_hasher->CheckPassword($pw2, $hash) . "\n"; # prints 0 or nothing

# A correct hash for "test12345".
# Please note the use of single quotes to ensure that the dollar signs
# will be interpreted literally.
$hash = '$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0';

print $t_hasher->CheckPassword($pw1, $hash) . "\n"; # prints 1
print $t_hasher->CheckPassword($pw2, $hash) . "\n"; # prints 0 or nothing

?>
