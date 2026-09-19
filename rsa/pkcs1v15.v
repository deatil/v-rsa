module rsa

import rand
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
	mut encrypter := Encrypter.new()
	encrypter.with_random(mut random)
	encrypter.with_padding(.pkcs1_padding)

	return encrypter.encrypt(pubkey, msg)

}

// decrypt_pkcs1v15 decrypts a plaintext using RSA and the padding scheme from PKCS #1 v1.5.
pub fn decrypt_pkcs1v15(priv PrivateKey, ciphertext []u8) ![]u8 {
	mut encrypter := Encrypter.new()
	encrypter.with_padding(.pkcs1_padding)

	return encrypter.decrypt(priv, ciphertext)
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

	em := decrypt_without_check(priv, ciphertext)!

	return rsa_pkcs1_type_2_unpad_internal(em)
}

pub fn encrypt_privatekey_pkcs1v15(priv PrivateKey, msg []u8) ![]u8 {
	mut encrypter := Encrypter.new()
	encrypter.with_padding(.pkcs1_padding)

	return encrypter.encrypt_privatekey(priv, msg)
}

pub fn decrypt_publickey_pkcs1v15(pubkey PublicKey, ciphertext []u8) ![]u8 {
	mut encrypter := Encrypter.new()
	encrypter.with_padding(.pkcs1_padding)

	return encrypter.decrypt_publickey(pubkey, ciphertext)
}
