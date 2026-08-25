module rsa

import math.big

const big_zero = big.zero_int
const big_one  = big.one_int

pub struct PublicKey {
pub mut:
    n big.Integer // modulus
    e int         // public exponent
}

// Size returns the modulus size in bytes.
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

fn check_pub(p PublicKey) ! {
    if p.n == big_zero {
        return error('v-rsa: missing public modulus')
    }

    if p.e < 2 {
        return error('v-rsa: public exponent too small')
    }

    // ensure fits 32-bit signed
    if p.e > (1<<31)-1 {
        return error('v-rsa: public exponent too large')
    }
}

pub struct PrivateKey {
    PublicKey               // embed public part
pub mut:
    d big.Integer            // private exponent
    primes []big.Integer     // prime factors (>= 2)
    precomputed PrecomputedValues
}

pub fn (priv PrivateKey) public() PublicKey {
    return priv.PublicKey
}

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
    dp big.Integer
    dq big.Integer
    q_inv big.Integer
    crt_values []CRTValue
}

pub struct CRTValue {
pub mut:
    exp   big.Integer
    coeff big.Integer
    r     big.Integer
}

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

pub fn (mut priv PrivateKey) precompute() ! {
    if priv.precomputed.dp.int() != 0 {
        return
    }
    
    priv.precomputed.dp = priv.primes[0] - big_one
    priv.precomputed.dp = priv.d % priv.precomputed.dp

    priv.precomputed.dq = priv.primes[1] - big_one
    priv.precomputed.dq = priv.d % priv.precomputed.dq

    priv.precomputed.q_inv = priv.primes[1].mod_inverse(priv.primes[0])!

    mut r := priv.primes[0] * priv.primes[1] // placeholder mul two-arg version
    priv.precomputed.crt_values = []CRTValue{len: priv.primes.len - 2}
    for i := 2; i < priv.primes.len; i++ {
        prime := priv.primes[i]

        mut values := &priv.precomputed.crt_values[i-2]

        values.exp = prime - big_one
        values.exp = priv.d % values.exp

        values.r = r + big_zero
        values.coeff = r.mod_inverse(prime)!

        r = r * prime
    }
}
