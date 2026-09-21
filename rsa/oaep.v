module rsa

import rand
import hash

// OAEPOptions corresponds to options for OAEP decryption.
@[params]
pub struct OAEPOptions {
pub:
	// hash is the hash function that will be used when generating the mask.
	hash &hash.Hash = unsafe { nil }

	// mgf_hash is the hash function used for MGF1.
	mgf_hash &hash.Hash = unsafe { nil }

	// label is an arbitrary byte string that must be equal to the value
	// used when encrypting.
	label []u8 = []
}

// encrypt_oaep encrypts the given message with RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.new() is a reasonable choice.
//
// The random parameter is used as a source of entropy to ensure that
// encrypting the same message twice doesn't result in the same ciphertext.
//
// The label parameter may contain arbitrary data that will not be encrypted,
// but which gives important context to the message. For example, if a given
// public key is used to encrypt two types of messages then distinct label
// values could be used to ensure that a ciphertext for one purpose cannot be
// used for another by an attacker. If not required it can be empty.
//
// The message must be no longer than the length of the public modulus minus
// twice the hash length, minus a further 2.
pub fn encrypt_oaep(mut h hash.Hash, mut random rand.PRNG, pubkey PublicKey, msg []u8, label []u8) ![]u8 {
	return encrypt_oaep_internal(mut h, mut h, mut random, pubkey, msg, label)
}

// decrypt_oaep decrypts ciphertext using RSA-OAEP.
//
// OAEP is parameterised by a hash function that is used as a random oracle.
// Encryption and decryption of a given message must use the same hash function
// and sha256.new() is a reasonable choice.
pub fn decrypt_oaep(mut h hash.Hash, priv PrivateKey, ciphertext []u8, label []u8) ![]u8 {
	return decrypt_oaep_internal(mut h, mut h, priv, ciphertext, label)
}

// encrypt_oaep_with_opts encrypts the given message with RSA-OAEP using the
// provided options.
//
// This function should only be used over [encrypt_oaep] when there is a need to
// specify the OAEP and MGF1 hashes separately.
pub fn encrypt_oaep_with_opts(mut random rand.PRNG, pubkey PublicKey, msg []u8, opts OAEPOptions) ![]u8 {
	if opts.hash == unsafe { nil } {
		return error('v-rsa: oaep hash not set')
	}

	mut h := hash.Hash(opts.hash)
	mut mgf_h := hash.Hash(opts.hash)

	if opts.mgf_hash != unsafe { nil } {
		mgf_h = hash.Hash(opts.mgf_hash)
	}

	label := opts.label

	return encrypt_oaep_internal(mut h, mut mgf_h, mut random, pubkey, msg, label)
}

// decrypt_oaep_with_opts decrypts the given message with RSA-OAEP using the
// provided options.
//
// This function should only be used over [decrypt_oaep] when there is a need to
// specify the OAEP and MGF1 hashes separately.
pub fn decrypt_oaep_with_opts(priv PrivateKey, ciphertext []u8, opts OAEPOptions) ![]u8 {
	if opts.hash == unsafe { nil } {
		return error('v-rsa: oaep hash not set')
	}

	mut h := hash.Hash(opts.hash)
	mut mgf_h := hash.Hash(opts.hash)

	if opts.mgf_hash != unsafe { nil } {
		mgf_h = hash.Hash(opts.mgf_hash)
	}

	label := opts.label

	return decrypt_oaep_internal(mut h, mut mgf_h, priv, ciphertext, label)
}

fn encrypt_oaep_internal(mut h hash.Hash, mut mgf_h hash.Hash, mut random rand.PRNG, pubkey PublicKey, msg []u8, label []u8) ![]u8 {
	mut encrypter := Encrypter.new()
	encrypter.with_random(mut random)
	encrypter.with_padding(.oaep_padding)
	encrypter.with_hash(mut h)
	encrypter.with_mgf_hash(mut mgf_h)
	encrypter.with_label(label)

	c := encrypter.encrypt(pubkey, msg)!

	return c
}

fn decrypt_oaep_internal(mut h hash.Hash, mut mgf_h hash.Hash, priv PrivateKey, ciphertext []u8, label []u8) ![]u8 {
	mut encrypter := Encrypter.new()
	encrypter.with_padding(.oaep_padding)
	encrypter.with_hash(mut h)
	encrypter.with_mgf_hash(mut mgf_h)
	encrypter.with_label(label)

	m := encrypter.decrypt(priv, ciphertext)!

	return m
}
