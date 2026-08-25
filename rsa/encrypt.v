module rsa

import hash
import math.big

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

// mgf1XOR XORs the bytes in out with mask generated using MGF1
fn mgf1_xor(mut out []u8, mut h hash.Hash, seed []u8) ! {
    mut counter := [u8(0),0,0,0]
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

fn encrypt(pubkey PublicKey, m big.Integer) !big.Integer {
	e := big.integer_from_int(pubkey.e)
    mut m2 := m + big_zero
	c := m2.big_mod_pow(e, pubkey.n)!
	return c
}

fn decrypt(priv PrivateKey, c big.Integer) !big.Integer {
    if c > priv.n {
        return error('v-rsa: decryption error')
    }

    if priv.n.signum == 0 {
        return error('v-rsa: decryption error')
    }

    mut m := big.Integer{}
    if priv.precomputed.dp.int() == 0 {
        // m = c^d mod n
        mut cc := bigint_copy(c)
        m = cc.big_mod_pow(priv.d, priv.n)!
    } else {
        mut cc := bigint_copy(c)

        // use CRT path
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

    return m
}

fn decrypt_and_check(priv PrivateKey, c big.Integer) !big.Integer {
    m := decrypt(priv, c)!

    check := encrypt(priv.PublicKey, m)!
    if !(c == check) {
        return error('v-rsa: internal error')
    }

    return m
}
