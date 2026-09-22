module rsa

import rand
import math
import math.big

// generate_key generates an RSA keypair of the given bit size using the
// random source random (for example, rand.new_default()).
pub fn generate_x931_key(mut random rand.PRNG, bits int) !PrivateKey {
	return generate_x931_multi_prime_key(mut random, 2, bits)
}

pub fn generate_x931_multi_prime_key(mut random rand.PRNG, nprimes int, bits int) !PrivateKey {
	mut priv := PrivateKey{}
	priv.PublicKey.e = 65537

	if nprimes < 2 {
		return error('v-rsa: generate_x931_multi_prime_key: nprimes must be >= 2')
	}

	if bits < 64 {
		prime_limit := f64(u64(1) << u32(bits / nprimes))
		// pi approximates the number of primes less than primeLimit
		mut pi := prime_limit / (math.log(prime_limit) - 1.0)
		// Generated primes start with 11 (in binary) so we can only
		// use a quarter of them.
		pi /= 4.0
		// Use a factor of two to ensure that key generation terminates
		// in a reasonable amount of time.
		pi /= 2.0
		if pi <= f64(nprimes) {
			return error('v-rsa: too few primes of given length to generate an RSA key')
		}
	}

	big4 := big.integer_from_int(4)
	big3 := big.integer_from_int(3)

	mut primes := []big.Integer{len: nprimes}

	for {
		mut todo := bits

		if nprimes >= 7 {
			todo += (nprimes - 2) / 5
		}

		for i := 0; i < nprimes; i++ {
			primes[i] = rand_prime(mut random, todo / (nprimes - i))!
			todo -= primes[i].bit_len()
		}

		// Make sure that primes is pairwise unequal.
		for i, prime in primes {
			// if prime % 4 == 3, it is true
			prime_rem := prime % big4
			if !(prime_rem == big3) {
				continue
			}

			for j := 0; j < i; j++ {
				if prime == primes[j] {
					continue
				}
			}
		}

		mut n := big.integer_from_int(1)
		mut totient := big.integer_from_int(1)
		for prime in primes {
			n = n * prime
			pminus1 := prime - big_one
			totient = totient * pminus1
		}

		if n.bit_len() != bits {
			// This should never happen for nprimes == 2 because
			// crypto/rand should set the top two bits in each prime.
			// For nprimes > 2 we hope it does not happen often.
			continue
		}

		mut e := big.integer_from_int(priv.e)

		// placeholder: compute D = e^-1 mod totient
		if d := e.mod_inverse(totient) {
			priv.d = d
			priv.primes = primes
			priv.PublicKey.n = n
			break
		}
	}

	priv.precompute()!
	return priv
}
