module rsa

import math.big
import rand.seed
import rand.mt19937

pub fn test_bigint_copy() {
	msg := 'cadaaec6a8f275e9dcd92223b185285f6cdd42dbc1382ddc28f9980a9179d544'

	a := big.integer_from_radix(msg, 16)!
	b := bigint_copy(a)
	assert a == b

	a_hex := a.hex()
	assert msg == a_hex

	b_hex := b.hex()
	assert msg == b_hex
}

pub fn test_rand_prime_fail() {
	seed_data := seed.time_seed_array(2)

	mut rnd := &mt19937.MT19937RNG{}
	rnd.seed(seed_data)

	mut need_err := false
	rand_prime(mut rnd, 1) or {
		assert 'v-rsa: prime size must be at least 2-bit' == err.msg()
		need_err = true
	}
	assert true == need_err
}

pub fn test_rand_prime() {
	seed_data := seed.time_seed_array(2)

	mut rnd := &mt19937.MT19937RNG{}
	rnd.seed(seed_data)

	p := rand_prime(mut rnd, 1024)!
	assert 1024 == p.bit_len()
}

pub fn test_non_zero_random_bytes() {
	seed_data := seed.time_seed_array(2)

	mut rnd := &mt19937.MT19937RNG{}
	rnd.seed(seed_data)

	mut s := []u8{len: 15}
	non_zero_random_bytes(mut s, mut rnd)
	assert 15 == s.len
	assert 0 != s[3]
}

pub fn test_rand_int() {
	seed_data := seed.time_seed_array(2)

	mut rnd := &mt19937.MT19937RNG{}
	rnd.seed(seed_data)

	max := big.integer_from_radix('9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767', 16)!

	p := rand_int(mut rnd, max)!
	assert p < max
}

pub fn test_find_bytes_index() {
	mut i := find_bytes_index([u8(0x2d), 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01], 0x86)
	assert 6 == i

	i = find_bytes_index([u8(0x2d), 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01], 0x01)
	assert 8 == i

	i = find_bytes_index([u8(0x2d), 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01], 0x02)
	assert -1 == i

	i = find_bytes_index([], 0x02)
	assert -1 == i
}
