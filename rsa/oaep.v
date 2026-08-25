module rsa

import rand
import hash
import math.big
import subtle

// OAEPOptions corresponds to options for OAEP decryption.
@[params]
pub struct OAEPOptions {
pub:
	// Hash is the hash function that will be used when generating the mask.
	hash &hash.Hash = unsafe { nil }

	// MGFHash is the hash function used for MGF1.
	mgf_hash &hash.Hash = unsafe { nil }

	// Label is an arbitrary byte string that must be equal to the value
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
	check_pub(pubkey)!

	k := pubkey.size()

	hash_size := h.size()
	if msg.len > k - 2 * hash_size - 2 {
		return ErrMessageTooLong{}
	}

	h.reset()
	h.write(label)!
	l_hash := h.sum([])

	mut em := []u8{len: k}
	mut seed := []u8{len: hash_size}
	mut db := []u8{len: k - (1 + hash_size)}

	copy(mut db[0..hash_size], l_hash)
	db[db.len - msg.len - 1] = 1
	copy(mut db[db.len - msg.len..], msg)

	rand_read_full(mut random, mut seed)

	mgf1_xor(mut db, mut mgf_h, seed)!
	mgf1_xor(mut seed, mut mgf_h, db)!

	copy(mut em[1..1 + hash_size], seed)
	copy(mut em[1 + hash_size..], db)

	m := big.integer_from_bytes(em)
	c := encrypt(pubkey, m)!

	mut out := []u8{len: k}

	c_bytes, _ := c.bytes()
	copy(mut out[k - c_bytes.len..], c_bytes)

	return out
}

fn decrypt_oaep_internal(mut h hash.Hash, mut mgf_h hash.Hash, priv PrivateKey, ciphertext []u8, label []u8) ![]u8 {
	check_pub(priv.public())!

	k := priv.public().size()

	if ciphertext.len > k || k < h.size() * 2 + 2 {
		return ErrDecryption{}
	}

	c := big.integer_from_bytes(ciphertext)

	m := decrypt(priv, c)!

	h.reset()
	h.write(label)!
	l_hash := h.sum([])

	mut em := []u8{len: k}
	m_bytes, _ := m.bytes()
	copy(mut em[k - m_bytes.len..], m_bytes)

	first_byte_is_zero := subtle.constant_time_byte_eq(em[0], 0)

	mut seed := em[1..h.size() + 1].clone()
	mut db := em[h.size() + 1..].clone()

	mgf1_xor(mut seed, mut mgf_h, db)!
	mgf1_xor(mut db, mut mgf_h, seed)!

	l_hash2 := db[0..h.size()].clone()

	l_hash2_good := subtle.constant_time_compare(l_hash, l_hash2)

	mut looking_for_index := int(1)
	mut index := int(0)
	mut invalid := int(0)

	rest := db[h.size()..].clone()

	for i := 0; i < rest.len; i++ {
		equals0 := subtle.constant_time_byte_eq(rest[i], 0)
		equals1 := subtle.constant_time_byte_eq(rest[i], 1)

		index = subtle.constant_time_select(looking_for_index & equals1, i, index)
		looking_for_index = subtle.constant_time_select(equals1, 0, looking_for_index)
		invalid = subtle.constant_time_select(looking_for_index & ~equals0, 1, invalid)
	}

	if first_byte_is_zero & l_hash2_good & ~invalid & ~looking_for_index != 1 {
		return ErrDecryption{}
	}

	return rest[index + 1..]
}
