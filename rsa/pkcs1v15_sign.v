module rsa

import hash
import crypto.md5
import crypto.sha1
import crypto.sha256
import crypto.sha512
import crypto.ripemd160
import subtle

pub interface IHasher {
	hash_prefixe() []u8
	hash_size() int
	hash_msg(msg []u8) ![]u8
}

// These are ASN1 DER structures:
//   DigestInfo ::= SEQUENCE {
//     digestAlgorithm AlgorithmIdentifier,
//     digest OCTET STRING
//   }
// For performance, we don't use the generic ASN1 encoder. Rather, we
// precompute a prefix of the digest value that makes a valid ASN1 DER string
// with the correct contents.
pub struct Hasher {
pub:
	prefixe []u8
	hash    fn () hash.Hash = unsafe { nil }
}

pub fn (h Hasher) hash_prefixe() []u8 {
	return h.prefixe.clone()
}

pub fn (h Hasher) hash_size() int {
	mut d := h.hash()
	return d.size()
}

pub fn (h Hasher) hash_msg(msg []u8) ![]u8 {
	mut d := h.hash()
	d.reset()
	d.write(msg)!
	return d.sum([])
}

pub const hasher_none = Hasher{
	prefixe: []
}
pub const hasher_md5 = Hasher{
	prefixe: [u8(0x30), 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02,
		0x05, 0x05, 0x00, 0x04, 0x10]
	hash:    fn () hash.Hash {
		return md5.new()
	}
}
pub const hasher_sha1 = Hasher{
	prefixe: [u8(0x30), 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
		0x04, 0x14]
	hash:    fn () hash.Hash {
		return sha1.new()
	}
}
pub const hasher_sha224 = Hasher{
	prefixe: [u8(0x30), 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
		0x02, 0x04, 0x05, 0x00, 0x04, 0x1c]
	hash:    fn () hash.Hash {
		return sha256.new224()
	}
}
pub const hasher_sha256 = Hasher{
	prefixe: [u8(0x30), 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
		0x02, 0x01, 0x05, 0x00, 0x04, 0x20]
	hash:    fn () hash.Hash {
		return sha256.new()
	}
}
pub const hasher_sha384 = Hasher{
	prefixe: [u8(0x30), 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
		0x02, 0x02, 0x05, 0x00, 0x04, 0x30]
	hash:    fn () hash.Hash {
		return sha512.new384()
	}
}
pub const hasher_sha512 = Hasher{
	prefixe: [u8(0x30), 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
		0x02, 0x03, 0x05, 0x00, 0x04, 0x40]
	hash:    fn () hash.Hash {
		return sha512.new()
	}
}
pub const hasher_sha512_224 = Hasher{
	prefixe: [u8(0x30), 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
		0x02, 0x05, 0x05, 0x00, 0x04, 0x1C]
	hash:    fn () hash.Hash {
		return sha512.new512_224()
	}
}
pub const hasher_sha512_256 = Hasher{
	prefixe: [u8(0x30), 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
		0x02, 0x06, 0x05, 0x00, 0x04, 0x20]
	hash:    fn () hash.Hash {
		return sha512.new512_256()
	}
}
pub const hasher_sha3_224 = Hasher{
	prefixe: [u8(0x30), 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
		0x02, 0x07, 0x05, 0x00, 0x04, 0x1C]
	hash:    fn () hash.Hash {
		return new_sha3_224()
	}
}
pub const hasher_sha3_256 = Hasher{
	prefixe: [u8(0x30), 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
		0x02, 0x08, 0x05, 0x00, 0x04, 0x20]
	hash:    fn () hash.Hash {
		return new_sha3_256()
	}
}
pub const hasher_sha3_384 = Hasher{
	prefixe: [u8(0x30), 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
		0x02, 0x09, 0x05, 0x00, 0x04, 0x30]
	hash:    fn () hash.Hash {
		return new_sha3_384()
	}
}
pub const hasher_sha3_512 = Hasher{
	prefixe: [u8(0x30), 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
		0x02, 0x0a, 0x05, 0x00, 0x04, 0x40]
	hash:    fn () hash.Hash {
		return new_sha3_512()
	}
}
pub const hasher_ripemd160 = Hasher{
	prefixe: [u8(0x30), 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04,
		0x14]
	hash:    fn () hash.Hash {
		return ripemd160.new()
	}
}
/*
pub const hasher_sm3 = Hasher{
	prefixe: [u8(0x30), 0x30, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x81, 0x1c, 0xcf, 0x55, 0x01, 0x83, 0x78, 0x05, 0x00, 0x04, 0x20]
	hash:    fn () hash.Hash {
		return sm3.new()
	}
}
*/

// sign_pkcs1v15 calculates the signature of hashed using
// RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5.  Note that hashed must
// be the result of hashing the input message using the given hash
// function. If hash is zero, hashed is signed directly. This isn't
// advisable except for interoperability.
pub fn sign_pkcs1v15(priv PrivateKey, hasher IHasher, hashed []u8) ![]u8 {
	prefix := pkcs1v15_hash_info(hasher, hashed.len)!

	k := priv.size()
	em := emsa_pkcs1v15_encode(hashed, k, prefix)!

	s := decrypt_with_check(priv, em)!
	return s
}

// verify_pkcs1v15 verifies an RSA PKCS #1 v1.5 signature.
// hashed is the result of hashing the input message using the given hash
// function and sig is the signature. A valid signature is indicated by
// returning a nil error. If hash is zero then hashed is used directly. This
// isn't advisable except for interoperability.
pub fn verify_pkcs1v15(pubkey PublicKey, hasher IHasher, hashed []u8, sig []u8) ! {
	prefix := pkcs1v15_hash_info(hasher, hashed.len)!

	k := pubkey.size()
	t_len := prefix.len + hashed.len
	if k < t_len + 11 {
		return ErrVerification{}
	}

	em := encrypt(pubkey, sig)!

	emsa_pkcs1v15_verify(hashed, em, k, prefix)!
}

fn emsa_pkcs1v15_encode(m_hash []u8, em_len int, prefix []u8) ![]u8 {
	h_len := m_hash.len
	t_len := prefix.len + h_len

	if em_len < t_len + 11 {
		return ErrMessageTooLong{}
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T
	mut em := []u8{len: em_len}
	em[1] = 1
	for i := 2; i < em_len - t_len - 1; i++ {
		em[i] = 0xff
	}

	copy(mut em[em_len - t_len..em_len - h_len], prefix)
	copy(mut em[em_len - h_len..em_len], m_hash)

	return em
}

fn emsa_pkcs1v15_verify(m_hash []u8, em []u8, em_len int, prefix []u8) ! {
	h_len := m_hash.len
	t_len := prefix.len + h_len
	if em_len < t_len + 11 {
		return ErrVerification{}
	}

	// RFC 8017 Section 8.2.2: If the length of the signature S is not k
	// octets (where k is the length in octets of the RSA modulus n), output
	// "invalid signature" and stop.
	if em_len != em.len {
		return ErrVerification{}
	}

	// EM = 0x00 || 0x01 || PS || 0x00 || T

	mut ok := subtle.constant_time_byte_eq(em[0], 0)
	ok &= subtle.constant_time_byte_eq(em[1], 1)
	ok &= subtle.constant_time_compare(em[em_len - h_len..em_len], m_hash)
	ok &= subtle.constant_time_compare(em[em_len - t_len..em_len - h_len], prefix)
	ok &= subtle.constant_time_byte_eq(em[em_len - t_len - 1], 0)

	for i := 2; i < em_len - t_len - 1; i++ {
		ok &= subtle.constant_time_byte_eq(em[i], 0xff)
	}

	if ok != 1 {
		return ErrVerification{}
	}
}

fn pkcs1v15_hash_info(hasher IHasher, in_len int) ![]u8 {
	prefix := hasher.hash_prefixe()
	if prefix.len == 0 {
		return []u8{}
	}

	hash_len := hasher.hash_size()
	if in_len != hash_len {
		return error('v-rsa: input must be hashed message')
	}

	return prefix
}
