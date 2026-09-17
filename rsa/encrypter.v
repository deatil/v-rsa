module rsa

import rand

// RSA padding list
pub enum RsaPadding {
	pkcs1_padding
	x931_padding
	no_padding
}

@[params]
pub struct EncrypterOptions {
pub:
	padding RsaPadding = .pkcs1_padding
}

pub fn encrypt_with_opts(mut random rand.PRNG, pubkey PublicKey, msg []u8, opts EncrypterOptions) ![]u8 {
	check_pub(pubkey)!

	k := pubkey.size()

	em := match opts.padding {
		.pkcs1_padding {
			rsa_pkcs1_type_2_pad(mut random, k, msg)!
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

pub fn decrypt_with_opts(priv PrivateKey, ciphertext []u8, opts EncrypterOptions) ![]u8 {
	check_pub(priv.PublicKey)!

	k := priv.size()

	em := decrypt_without_check(priv, ciphertext)!

	m := match opts.padding {
		.pkcs1_padding {
			rsa_pkcs1_type_2_unpad(k, em)!
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

pub fn encrypt_privatekey_with_opts(priv PrivateKey, msg []u8, opts EncrypterOptions) ![]u8 {
	check_pub(priv.PublicKey)!

	k := priv.size()

	em := match opts.padding {
		.pkcs1_padding {
			rsa_pkcs1_type_1_pad(k, msg)!
		}
		.x931_padding {
			rsa_x931_pad(k, msg)!
		}
		.no_padding {
			rsa_no_pad(k, msg)!
		}
	}

	c := encrypt_privatekey(priv, em, opts)!

	return c
}

pub fn decrypt_publickey_with_opts(pubkey PublicKey, ciphertext []u8, opts EncrypterOptions) ![]u8 {
	check_pub(pubkey)!

	k := pubkey.size()

	em := decrypt_publickey(pubkey, ciphertext, opts)!

	m := match opts.padding {
		.pkcs1_padding {
			rsa_pkcs1_type_1_unpad(k, em)!
		}
		.x931_padding {
			rsa_x931_unpad(k, em)!
		}
		.no_padding {
			rsa_no_unpad(k, em)!
		}
	}

	return m
}
