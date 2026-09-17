module rsa

import hash
import math.big

// incCounter increments a four byte, big-endian counter.
fn inc_counter(mut c []u8) {
	// big-endian 4 byte increment
	c[3] += 1
	if c[3] != 0 {
		return
	}

	c[2] += 1
	if c[2] != 0 {
		return
	}

	c[1] += 1
	if c[1] != 0 {
		return
	}

	c[0] += 1
}

// mgf1_xor XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS #1 v2.1.
fn mgf1_xor(mut out []u8, mut h hash.Hash, seed []u8) ! {
	mut counter := [u8(0), 0, 0, 0]
	mut digest := []u8{}

	mut done := 0
	for done < out.len {
		h.reset()
		h.write(seed)!
		h.write(counter[0..4])!
		digest = h.sum([])

		for i := 0; i < digest.len && done < out.len; i++ {
			out[done] ^= digest[i]
			done++
		}

		inc_counter(mut counter[0..])
	}
}

fn encrypt(pubkey PublicKey, plaintext []u8) ![]u8 {
	m := big.integer_from_bytes(plaintext)

	e := big.integer_from_int(pubkey.e)
	c := m.big_mod_pow(e, pubkey.n)!

	k := pubkey.size()
	out := bigint_bytes(c, k)
	return out
}

// decrypt performs an RSA decryption, resulting in a plaintext integer. If a
// random source is given, RSA blinding is used.
fn decrypt(priv PrivateKey, ciphertext []u8, check bool) ![]u8 {
	c := big.integer_from_bytes(ciphertext)

	if c > priv.n {
		return ErrDecryption{}
	}

	if priv.n.signum == 0 {
		return ErrDecryption{}
	}

	mut m := big.Integer{}
	if priv.precomputed.dp.int() == 0 {
		// m = c^d mod n
		mut cc := bigint_copy(c)
		m = cc.big_mod_pow(priv.d, priv.n)!
	} else {
		mut cc := bigint_copy(c)

		// We have the precalculated values needed for the CRT.
		m = cc.big_mod_pow(priv.precomputed.dp, priv.primes[0])!
		mut m2 := cc.big_mod_pow(priv.precomputed.dq, priv.primes[1])!
		m = m - m2

		if m.signum < 0 {
			m = m + priv.primes[0]
		}

		m = m * priv.precomputed.q_inv
		m = m % priv.primes[0]
		m = m * priv.primes[1]
		m = m + m2
		for i, values in priv.precomputed.crt_values {
			prime := priv.primes[2 + i]
			m2 = cc.big_mod_pow(values.exp, prime)!
			m2 = m2 - m
			m2 = m2 * values.coeff
			m2 = m2 % prime
			if m2.signum < 0 {
				m2 = m2 + prime
			}
			m2 = m2 * values.r
			m = m + m2
		}
	}

	if check {
		e := big.integer_from_int(priv.e)
		c2 := m.big_mod_pow(e, priv.n)!

		if !(c == c2) {
			return error('v-rsa: internal error')
		}
	}

	k := priv.size()
	out := bigint_bytes(m, k)
	return out
}

const with_check = true
const no_check = false

fn decrypt_without_check(priv PrivateKey, ciphertext []u8) ![]u8 {
	return decrypt(priv, ciphertext, no_check)
}

fn decrypt_with_check(priv PrivateKey, ciphertext []u8) ![]u8 {
	return decrypt(priv, ciphertext, with_check)
}

// ========

fn encrypt_privatekey(priv PrivateKey, plaintext []u8, opts EncrypterOptions) ![]u8 {
	pt := big.integer_from_bytes(plaintext)

	if pt > priv.n {
		return ErrDecryption{}
	}

	if priv.n.signum == 0 {
		return ErrDecryption{}
	}

	mut c := big.Integer{}
	if priv.precomputed.dp.int() == 0 {
		// c = pt^d mod n
		mut pt2 := bigint_copy(pt)
		c = pt2.big_mod_pow(priv.d, priv.n)!
	} else {
		mut pt2 := bigint_copy(pt)

		// We have the precalculated values needed for the CRT.
		c = pt2.big_mod_pow(priv.precomputed.dp, priv.primes[0])!
		mut c2 := pt2.big_mod_pow(priv.precomputed.dq, priv.primes[1])!
		c = c - c2

		if c.signum < 0 {
			c = c + priv.primes[0]
		}

		c = c * priv.precomputed.q_inv
		c = c % priv.primes[0]
		c = c * priv.primes[1]
		c = c + c2
		for i, values in priv.precomputed.crt_values {
			prime := priv.primes[2 + i]
			c2 = pt2.big_mod_pow(values.exp, prime)!
			c2 = c2 - c
			c2 = c2 * values.coeff
			c2 = c2 % prime
			if c2.signum < 0 {
				c2 = c2 + prime
			}
			c2 = c2 * values.r
			c = c + c2
		}
	}

	if opts.padding == .x931_padding {
		f := priv.n - c
		if f < c {
			c = bigint_copy(f)
		}
	}

	k := priv.size()
	out := bigint_bytes(c, k)
	return out
}

fn decrypt_publickey(pubkey PublicKey, ciphertext []u8, opts EncrypterOptions) ![]u8 {
	c := big.integer_from_bytes(ciphertext)

	e := big.integer_from_int(pubkey.e)
	mut m := c.big_mod_pow(e, pubkey.n)!

	bigint16 := big.integer_from_int(16)
	m2 := m % bigint16
	if (opts.padding == .x931_padding) && (m2.int() != 12) {
		m = pubkey.n - m
	}

	k := pubkey.size()
	out := bigint_bytes(m, k)
	return out
}
