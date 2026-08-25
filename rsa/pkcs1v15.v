module rsa

import rand
import math.big
import subtle

@[params]
pub struct PKCS1v15DecryptOptions {
pub:
    session_key_len int = 20
}

// encrypt_pkcs1v15 encrypts msg with PKCS#1 v1.5 padding.
pub fn encrypt_pkcs1v15(mut random rand.PRNG, pubkey PublicKey, msg []u8) ![]u8 {
    check_pub(pubkey)!

    k := pubkey.size()
    if msg.len > k - 11 {
        return error('v-rsa: message too long for RSA public key size')
    }
	
	// EM = 0x00 || 0x02 || PS || 0x00 || M
    mut em := []u8{len: k}
    em[1] = 2

    mut ps := []u8{len: (em.len - msg.len - 3)}
    mut mm := []u8{len: msg.len}

    non_zero_random_bytes(mut ps, mut random)
    em[em.len - msg.len - 1] = 0

	copy(mut mm, msg)

    copy(mut em[2..(em.len - msg.len - 1)], ps)
    copy(mut em[(em.len - msg.len)..], mm)

    m := big.integer_from_bytes(em)
    c := encrypt(pubkey, m)!

    mut out := []u8{len: k}

    c_bytes, _ := c.bytes()
    copy(mut out[k - c_bytes.len ..], c_bytes)

    return out
}

// decrypt_pkcs1v15 decrypts a plaintext using RSA and the padding scheme from PKCS #1 v1.5.
pub fn decrypt_pkcs1v15(priv PrivateKey, ciphertext []u8) ![]u8 {
    check_pub(priv.PublicKey)!

    valid, out, index := decrypt_pkcs1v15_internal(priv, ciphertext)!

    if valid == 0 {
        return ErrDecryption{}
    }

    return out[index..]
}

// decrypt_pkcs1v15_session_key decrypts a session key using RSA and the padding scheme from PKCS #1 v1.5.
pub fn decrypt_pkcs1v15_session_key(priv PrivateKey, ciphertext []u8, mut key []u8) ! {
    check_pub(priv.PublicKey)!

    k := priv.size()
    if k - (key.len + 3 + 8) < 0 {
        return ErrDecryption{}
    }

    valid, em, index := decrypt_pkcs1v15_internal(priv, ciphertext)!

    if em.len != k {
        return ErrDecryption{}
    }

    mut valid2 := valid
    valid2 &= subtle.constant_time_eq(em.len - index, key.len)
    subtle.constant_time_copy(valid2, mut key, em[em.len - key.len..])
}

pub fn decrypt_pkcs1v15_session_key_with_opts(mut random rand.PRNG, priv PrivateKey, ciphertext []u8, opts PKCS1v15DecryptOptions) ![]u8 {
    mut plaintext := []u8{len: opts.session_key_len}
    rand_read_full(mut random, mut plaintext)

    decrypt_pkcs1v15_session_key(priv, ciphertext, mut plaintext)!

    return plaintext
}

// decrypt_pkcs1v15_internal decrypts and checks PKCS#1 v1.5 padding, returns valid flag, full em, index
fn decrypt_pkcs1v15_internal(priv PrivateKey, ciphertext []u8) !(int, []u8, int) {
    k := priv.size()
    if k < 11 {
        return ErrDecryption{}
    }

    c := big.integer_from_bytes(ciphertext)
    m := decrypt(priv, c)!

    mut em := []u8{len: k}
    m_bytes, _ := m.bytes()
    copy(mut em[k - m_bytes.len ..], m_bytes)

    first_byte_zero := subtle.constant_time_byte_eq(em[0], 0)
    second_byte_two := subtle.constant_time_byte_eq(em[1], 2)

    mut looking_for_index := 1
    mut index := 0
    for i := 2; i < em.len; i++ {
        equals0 := subtle.constant_time_byte_eq(em[i], 0)

        index = subtle.constant_time_select(looking_for_index & equals0, i, index)
        looking_for_index = subtle.constant_time_select(equals0, 0, looking_for_index)
    }

    valid_ps := subtle.constant_time_less_or_eq(2 + 8, index)
    valid := first_byte_zero & second_byte_two & (~looking_for_index & 1) & valid_ps
    real_index := subtle.constant_time_select(valid, index + 1, 0)

    return valid, em, real_index
}
