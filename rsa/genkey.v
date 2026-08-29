module rsa

import rand
import math
import math.big

// generate_key generates an RSA keypair of the given bit size using the
// random source random (for example, rand.new_default()).
pub fn generate_key(mut random rand.PRNG, bits int) !PrivateKey {
	return generate_multi_prime_key(mut random, 2, bits)
}

// generate_multi_prime_key generates a multi-prime RSA keypair of the given bit
// size and the given random source, as suggested in [1]. Although the public
// keys are compatible (actually, indistinguishable) from the 2-prime case,
// the private keys are not. Thus it may not be possible to export multi-prime
// private keys in certain formats or to subsequently import them into other
// code.
//
// Table 1 in [2] suggests maximum numbers of primes for a given size.
//
// [1] US patent 4405829 (1972, expired)
// [2] http://www.cacr.math.uwaterloo.ca/techreports/2006/cacr2006-16.pdf
pub fn generate_multi_prime_key(mut random rand.PRNG, nprimes int, bits int) !PrivateKey {
	mut priv := PrivateKey{}
	priv.PublicKey.e = 65537

	if nprimes < 2 {
		return error('v-rsa: GenerateMultiPrimeKey: nprimes must be >= 2')
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

	mut primes := []big.Integer{len: nprimes}

	for {
		mut todo := bits
		// rand.PRNG should set the top two bits in each prime.
		// Thus each prime has the form
		//   p_i = 2^bitlen(p_i) × 0.11... (in base 2).
		// And the product is:
		//   P = 2^todo × α
		// where α is the product of nprimes numbers of the form 0.11...
		//
		// If α < 1/2 (which can happen for nprimes > 2), we need to
		// shift todo to compensate for lost bits: the mean value of 0.11...
		// is 7/8, so todo + shift - nprimes * log2(7/8) ~= bits - 1/2
		// will give good results.
		if nprimes >= 7 {
			todo += (nprimes - 2) / 5
		}

		for i := 0; i < nprimes; i++ {
			primes[i] = rand_prime(mut random, todo / (nprimes - i))!
			todo -= primes[i].bit_len()
		}

		// Make sure that primes is pairwise unequal.
		for i, prime in primes {
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
