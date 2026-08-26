module rsa

import crypto.sha1

pub fn test_mgf1_xor() {
	mut out := []u8{len: 25}
	seed_byte := '12345678'.bytes()
	mut h := sha1.new()
	mgf1_xor(mut out, mut h, seed_byte)!

	assert '651b52269d52682b1dca3f14e1b56b5a7cf7bba576cd6363a3' == out.hex()
}
