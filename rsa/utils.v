module rsa

import rand
import math.big

pub fn bigint_copy(x big.Integer) big.Integer {
	return x + big.zero_int
}

pub fn rand_prime(mut random rand.PRNG, bits int) !big.Integer {
	if bits < 2 {
		return error("v-rsa: prime size must be at least 2-bit")
	}

	mut b := u32(bits % 8)
	if b == 0 {
		b = 8
	}

	mut bytes := []u8{len: (bits+7)/8}
	mut p := big.Integer{}

	for {
		rand_read_full(mut random, mut bytes)

		bytes[0] &= u8(int(1<<b) - 1)

		if b >= 2 {
			bytes[0] |= 3 << (b - 2)
		} else {
			// Here b==1, because b cannot be zero.
			bytes[0] |= 1
			if bytes.len > 1 {
				bytes[1] |= 0x80
			}
		}
		// Make the value odd since an even number this large certainly isn't prime.
		bytes[bytes.len-1] |= 1

		p = big.integer_from_bytes(bytes)
		if bigint_is_probable_prime(p) {
			break
		}
	}

	return p
}

pub fn rand_int(mut random rand.PRNG, max big.Integer) !big.Integer {
	if max.signum <= 0 {
		return error("v-rsa: argument to Int is <= 0")
	}

	mut n := max - big_one

	// bit_len is the maximum bit length needed to encode a value < max.
	bit_len := n.bit_len()
	if bit_len == 0 {
		// the only valid result is 0
		return big.Integer{}
	}

	// k is the maximum byte length needed to encode a value < max.
	k := (bit_len + 7) / 8

	// b is the number of bits in the most significant byte of max-1.
	mut b := u32(bit_len % 8)
	if b == 0 {
		b = 8
	}

	mut bytes := []u8{len: k}

	for {
		rand_read_full(mut random, mut bytes)

		// Clear bits in the first byte to increase the probability
		// that the candidate is < max.
		bytes[0] &= u8(int(1<<b) - 1)

		n = big.integer_from_bytes(bytes)
		if n < max {
			break
		}
	}

	return n
}

pub fn rand_read_full(mut random rand.PRNG, mut bytes []u8) {
	mut rng := &rand.PRNG(random)
	rng.read(mut bytes)
}

pub fn non_zero_random_bytes(mut s []u8, mut random rand.PRNG) {
	rand_read_full(mut random, mut s)

	for i := 0; i < s.len; i++ {
		for s[i] == 0 {
			rand_read_full(mut random, mut s[i..i+1])

			// In tests, the PRNG may return all zeros so we do
			// this to break the loop.
			s[i] ^= 0x42
		}
	}
}

pub fn find_bytes_index(data []u8, val u8) int {
	if data.len == 0 {
		return 0
	}

	for i, item in data {
		if item == val {
			return i
		}
	}

	return 0
}

pub fn bigint_is_probable_prime(n big.Integer) bool {
	if n.signum <= 0 {
		return false
	}
	if n == big.zero_int || n == big.one_int {
		return false
	}
	if n == big.integer_from_u64(2) || n == big.integer_from_u64(3) {
		return true
	}
	if !n.get_bit(0) {
		return false
	}

	// Optional: still do a small-primes trial division for speed
	small_primes := [u64(2), 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
	for p in small_primes {
		p_int := big.integer_from_u64(p)
		if n == p_int {
			return true
		}
		if (n % p_int).signum == 0 {
			return false
		}
	}

	// Standard witness list (good deterministic set for 64-bit; probabilistic for larger)
	witnesses := [u64(2), 325, 9375, 28178, 450775, 9780504, 1795265022]

	return miller_rabin_test(n, witnesses)
}

fn miller_rabin_test(n big.Integer, witnesses []u64) bool {
	// write n - 1 as d * 2^s with d odd
	n_minus_one := n - big.one_int
	mut d := n_minus_one
	mut s := u32(0)
	for d.get_bit(0) == false {
		d = d.right_shift(1)
		s++
	}

	for witness in witnesses {
		// base a = witness % n
		mut a := big.integer_from_u64(witness)
		// reduce base modulo n
		if a.abs_cmp(n) >= 0 {
			a = a % n
		}
		// if base == 0 or 1 then it's a trivial witness -> skip
		if a.signum == 0 || a == big.one_int {
			continue
		}

		// x = a^d mod n
		mut x := a.big_mod_pow(d, n) or { 
			return false 
		}
		if x == big.one_int || x == n_minus_one {
			continue
		}

		mut composite := true
		mut r := u32(1)
		for r < s {
			// x = x^2 mod n
			x = (x * x) % n
			if x == n_minus_one {
				composite = false
				break
			}
			r++
		}

		if composite {
			return false
		}
	}

	return true
}
