module rsa

import rand
import hash

// RSA padding list
pub enum RsaPadding {
	pkcs1_padding
	oaep_padding
	x931_padding
	no_padding
}

pub struct Encrypter {
mut:
	// padding type
	padding RsaPadding = .pkcs1_padding

	// rand
	random &rand.PRNG = unsafe { nil }

	// hash is the hash function that will be used when generating the mask.
	hash &hash.Hash = unsafe { nil }

	// mgf_hash is the hash function used for MGF1.
	mgf_hash &hash.Hash = unsafe { nil }

	// label is an arbitrary byte string that must be equal to the value
	// used when encrypting.
	label []u8 = []
}

pub fn Encrypter.new() &Encrypter {
	e := &Encrypter{}
	return e
}

pub fn (mut e Encrypter) with_padding(padding RsaPadding) {
	e.padding = padding
}

pub fn (mut e Encrypter) with_random(mut random rand.PRNG) {
	e.random = random
}

pub fn (mut e Encrypter) with_hash(mut h hash.Hash) {
	e.hash = h
}

pub fn (mut e Encrypter) with_mgf_hash(mut h hash.Hash) {
	e.mgf_hash = h
}

pub fn (mut e Encrypter) with_label(label []u8) {
	e.label = label
}

pub fn (e &Encrypter) encrypt(pubkey PublicKey, msg []u8) ![]u8 {
	check_pub(pubkey)!

	k := pubkey.size()

	em := match e.padding {
		.pkcs1_padding {
			mut random := e.random
			rsa_pkcs1_type_2_pad(mut random, k, msg)!
		}
		.oaep_padding {
			mut random := e.random

			mut h := hash.Hash(e.hash)
			mut mgf_h := hash.Hash(e.hash)

			if e.mgf_hash != unsafe { nil } {
				mgf_h = hash.Hash(e.mgf_hash)
			}

			label := e.label

			rsa_oaep_pad(mut h, mut mgf_h, mut random, k, msg, label)!
		}
		.no_padding {
			rsa_no_pad(k, msg)!
		}
		else {
			return error('v-rsa: invalid padding type')
		}
	}

	c := encrypt(pubkey, em)!

	return c
}

pub fn (e &Encrypter) decrypt(priv PrivateKey, ciphertext []u8) ![]u8 {
	check_pub(priv.PublicKey)!

	k := priv.size()

	em := decrypt_without_check(priv, ciphertext)!

	m := match e.padding {
		.pkcs1_padding {
			rsa_pkcs1_type_2_unpad(k, em)!
		}
		.oaep_padding {
			mut h := hash.Hash(e.hash)
			mut mgf_h := hash.Hash(e.hash)

			if e.mgf_hash != unsafe { nil } {
				mgf_h = hash.Hash(e.mgf_hash)
			}

			label := e.label

			rsa_oaep_unpad(mut h, mut mgf_h, k, em, label)!
		}
		.no_padding {
			rsa_no_unpad(k, em)!
		}
		else {
			return error('v-rsa: invalid padding type')
		}
	}

	return m
}

pub fn (e &Encrypter) encrypt_privatekey(priv PrivateKey, msg []u8) ![]u8 {
	check_pub(priv.PublicKey)!

	k := priv.size()

	em := match e.padding {
		.pkcs1_padding {
			rsa_pkcs1_type_1_pad(k, msg)!
		}
		.x931_padding {
			rsa_x931_pad(k, msg)!
		}
		.no_padding {
			rsa_no_pad(k, msg)!
		}
		else {
			return error('v-rsa: invalid padding type')
		}
	}

	c := encrypt_privatekey(priv, em, e.padding)!

	return c
}

pub fn (e &Encrypter) decrypt_publickey(pubkey PublicKey, ciphertext []u8) ![]u8 {
	check_pub(pubkey)!

	k := pubkey.size()

	em := decrypt_publickey(pubkey, ciphertext, e.padding)!

	m := match e.padding {
		.pkcs1_padding {
			rsa_pkcs1_type_1_unpad(k, em)!
		}
		.x931_padding {
			rsa_x931_unpad(k, em)!
		}
		.no_padding {
			rsa_no_unpad(k, em)!
		}
		else {
			return error('v-rsa: invalid padding type')
		}
	}

	return m
}
