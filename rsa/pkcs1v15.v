module rsa

import rand
import math.big
import subtle

// This file implements encryption and decryption using PKCS #1 v1.5 padding.

// PKCS1v15DecrypterOpts is for passing options to PKCS #1 v1.5 decryption.
@[params]
pub struct PKCS1v15DecryptOptions {
pub:
	// session_key_len is the length of the session key that is being
	// decrypted. If not zero, then a padding error during decryption will
	// cause a random plaintext of this length to be returned rather than
	// an error. These alternatives happen in constant time.
	session_key_len int = 20
}

// encrypt_pkcs1v15 encrypts the given message with RSA and the padding
// scheme from PKCS #1 v1.5.  The message must be no longer than the
// length of the public modulus minus 11 bytes.
//
// The rand parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same
// ciphertext.
pub fn encrypt_pkcs1v15(mut random rand.PRNG, pubkey PublicKey, msg []u8) ![]u8 {
	check_pub(pubkey)!

	k := pubkey.size()
	if msg.len > k - 11 {
		return ErrMessageTooLong{}
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
	copy(mut out[k - c_bytes.len..], c_bytes)

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
		// This should be impossible because decrypt_pkcs1v15_internal always
		// returns the full slice.
		return ErrDecryption{}
	}

	mut valid2 := valid
	valid2 &= subtle.constant_time_eq(em.len - index, key.len)
	subtle.constant_time_copy(valid2, mut key, em[em.len - key.len..])
}

// decrypt_pkcs1v15_session_key_with_opts return session key bytes
pub fn decrypt_pkcs1v15_session_key_with_opts(mut random rand.PRNG, priv PrivateKey, ciphertext []u8, opts PKCS1v15DecryptOptions) ![]u8 {
	mut plaintext := []u8{len: opts.session_key_len}
	rand_read_full(mut random, mut plaintext)

	decrypt_pkcs1v15_session_key(priv, ciphertext, mut plaintext)!

	return plaintext
}

// decrypt_pkcs1v15_internal decrypts ciphertext using priv and blinds the operation if
// rand is not nil. It returns one or zero in valid that indicates whether the
// plaintext was correctly structured. In either case, the plaintext is
// returned in em so that it may be read independently of whether it was valid
// in order to maintain constant memory access patterns. If the plaintext was
// valid then index contains the index of the original message in em.
fn decrypt_pkcs1v15_internal(priv PrivateKey, ciphertext []u8) !(int, []u8, int) {
	k := priv.size()
	if k < 11 {
		return ErrDecryption{}
	}

	c := big.integer_from_bytes(ciphertext)
	m := decrypt(priv, c)!

	mut em := []u8{len: k}
	m_bytes, _ := m.bytes()
	copy(mut em[k - m_bytes.len..], m_bytes)

	first_byte_zero := subtle.constant_time_byte_eq(em[0], 0)
	second_byte_two := subtle.constant_time_byte_eq(em[1], 2)

	// The remainder of the plaintext must be a string of non-zero random
	// octets, followed by a 0, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the zero.
	//   index: the offset of the first zero byte.
	mut looking_for_index := 1

	mut index := 0
	for i := 2; i < em.len; i++ {
		equals0 := subtle.constant_time_byte_eq(em[i], 0)

		index = subtle.constant_time_select(looking_for_index & equals0, i, index)
		looking_for_index = subtle.constant_time_select(equals0, 0, looking_for_index)
	}

	// The PS padding must be at least 8 bytes long, and it starts two
	// bytes into em.
	valid_ps := subtle.constant_time_less_or_eq(2 + 8, index)

	valid := first_byte_zero & second_byte_two & (~looking_for_index & 1) & valid_ps
	real_index := subtle.constant_time_select(valid, index + 1, 0)

	return valid, em, real_index
}
