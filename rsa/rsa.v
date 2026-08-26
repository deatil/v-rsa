module rsa

import math.big

const big_zero = big.zero_int
const big_one = big.one_int

// A PublicKey represents the public part of an RSA key.
pub struct PublicKey {
pub mut:
	n big.Integer // modulus
	e int         // public exponent
}

// Size returns the modulus size in bytes. Raw signatures and ciphertexts
// for or by this public key will have the same size.
pub fn (p PublicKey) size() int {
	return (p.n.bit_len() + 7) / 8
}

// Equal reports whether pub and x have the same value.
// In V, we'll accept a PublicKey for equality check.
pub fn (p PublicKey) equal(x PublicKey) bool {
	if p.n == x.n && p.e == x.e {
		return true
	}

	return false
}

// A PrivateKey represents an RSA key
pub struct PrivateKey {
	PublicKey // embed public part
pub mut:
	d      big.Integer   // private exponent
	primes []big.Integer // prime factors (>= 2)

	// Precomputed contains precomputed values that speed up private
	// operations, if available.
	precomputed PrecomputedValues
}

// Public returns the public key corresponding to priv.
pub fn (priv PrivateKey) public() PublicKey {
	return priv.PublicKey
}

// Equal reports whether priv and x have equivalent values. It ignores
// Precomputed values.
pub fn (priv PrivateKey) equal(x PrivateKey) bool {
	if !priv.PublicKey.equal(x.public()) || !(priv.d == x.d) {
		return false
	}

	if priv.primes.len != x.primes.len {
		return false
	}

	for i := 0; i < priv.primes.len; i++ {
		if !(priv.primes[i] == x.primes[i]) {
			return false
		}
	}

	return true
}

pub struct PrecomputedValues {
pub mut:
	dp    big.Integer // D mod (P-1)
	dq    big.Integer // D mod (Q-1)
	q_inv big.Integer // Q^-1 mod P

	// CRTValues is used for the 3rd and subsequent primes. Due to a
	// historical accident, the CRT for the first two primes is handled
	// differently in PKCS #1 and interoperability is sufficiently
	// important that we mirror this.
	crt_values []CRTValue
}

// CRTValue contains the precomputed Chinese remainder theorem values.
pub struct CRTValue {
pub mut:
	exp   big.Integer // D mod (prime-1).
	coeff big.Integer // R·Coeff ≡ 1 mod Prime.
	r     big.Integer // product of primes prior to this (inc p and q).
}

// Validate performs basic sanity checks on the key.
// It returns nil if the key is valid, or else an error describing a problem.
pub fn (priv PrivateKey) validate() ! {
	check_pub(priv.public())!

	// Check Πprimes == n.
	mut modulus := big.integer_from_int(1)
	for prime in priv.primes {
		// Any primes ≤ 1 will cause divide-by-zero later.
		if prime < big_one || prime == big_one {
			return error('v-rsa: invalid prime value')
		}

		modulus = modulus * prime
	}

	if !(modulus == priv.n) {
		return error('v-rsa: invalid modulus')
	}

	// Check that de ≡ 1 mod p-1, for each prime.
	// This implies that e is coprime to each p-1 as e has a multiplicative
	// inverse. Therefore e is coprime to lcm(p-1,q-1,r-1,...) =
	// exponent(ℤ/nℤ). It also implies that a^de ≡ a mod p as a^(p-1) ≡ 1
	// mod p. Thus a^de ≡ a mod n for all a coprime to n, as required.
	mut de := big.integer_from_int(priv.e)
	de = de * priv.d
	for prime in priv.primes {
		pminus1 := prime - big_one

		// congruence = de mod (p-1)
		congruence := de % pminus1
		if !(congruence == big_one) {
			return error('v-rsa: invalid exponents')
		}
	}
}

// Precompute performs some calculations that speed up private key operations
// in the future.
pub fn (mut priv PrivateKey) precompute() ! {
	if priv.precomputed.dp.int() != 0 {
		return
	}

	priv.precomputed.dp = priv.d % (priv.primes[0] - big_one)
	priv.precomputed.dq = priv.d % (priv.primes[1] - big_one)
	priv.precomputed.q_inv = priv.primes[1].mod_inverse(priv.primes[0])!

	mut r := priv.primes[0] * priv.primes[1] // placeholder mul two-arg version
	priv.precomputed.crt_values = []CRTValue{len: priv.primes.len - 2}
	for i := 2; i < priv.primes.len; i++ {
		prime := priv.primes[i]

		mut values := &priv.precomputed.crt_values[i - 2]

		values.exp = priv.d % (prime - big_one)
		values.r = bigint_copy(r)
		values.coeff = r.mod_inverse(prime)!

		r = r * prime
	}
}

// checkPub sanity checks the public key before we use it.
// https://www.imperialviolet.org/2012/03/16/rsae.html.
fn check_pub(p PublicKey) ! {
	if p.n == big_zero {
		return error('v-rsa: missing public modulus')
	}

	if p.e < 2 {
		return error('v-rsa: public exponent too small')
	}

	// ensure fits 32-bit signed
	if p.e > (1 << 31) - 1 {
		return error('v-rsa: public exponent too large')
	}
}
