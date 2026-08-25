module rsa

import rand
import math
import math.big

pub fn generate_key(mut random rand.PRNG, bits int) !PrivateKey {
    return generate_multi_prime_key(mut random, 2, bits)
}

pub fn generate_multi_prime_key(mut random rand.PRNG, nprimes int, bits int) !PrivateKey {
	mut priv := PrivateKey{}
	priv.PublicKey.e = 65537
	
    if nprimes < 2 {
        return error('v-rsa: GenerateMultiPrimeKey: nprimes must be >= 2')
    }

    if bits < 64 {
        prime_limit := f64(u64(1) << u32(bits / nprimes))
        mut pi := prime_limit / (math.log(prime_limit) - 1.0)
        pi /= 4.0
        pi /= 2.0
        if pi <= f64(nprimes) {
            return error('v-rsa: too few primes of given length to generate an RSA key')
        }
    }

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