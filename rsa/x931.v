module rsa

import hash
import crypto.sha1
import crypto.sha256
import crypto.sha512
import subtle

pub interface IX931Hasher {
	hash_id() int
	hash_size() int
	hash_msg(msg []u8) ![]u8
}

pub struct X931Hasher {
pub:
	hashid int
	hash   fn () hash.Hash = unsafe { nil }
}

pub fn (h X931Hasher) hash_id() int {
	return h.hashid
}

pub fn (h X931Hasher) hash_size() int {
	mut d := h.hash()
	return d.size()
}

pub fn (h X931Hasher) hash_msg(msg []u8) ![]u8 {
	mut d := h.hash()
	d.reset()
	d.write(msg)!
	return d.sum([])
}

pub const x931_hasher_sha1 = X931Hasher{
	hashid: 0x33
	hash:   fn () hash.Hash {
		return sha1.new()
	}
}
pub const x931_hasher_sha256 = X931Hasher{
	hashid: 0x34
	hash:   fn () hash.Hash {
		return sha256.new()
	}
}
pub const x931_hasher_sha384 = X931Hasher{
	hashid: 0x36
	hash:   fn () hash.Hash {
		return sha512.new384()
	}
}
pub const x931_hasher_sha512 = X931Hasher{
	hashid: 0x35
	hash:   fn () hash.Hash {
		return sha512.new()
	}
}

pub fn sign_x931(priv PrivateKey, hasher IX931Hasher, hashed []u8) ![]u8 {
	hash_id := x931_hash_info(hasher, hashed.len)!

	k := priv.size()
	em := emsa_x931_encode(hashed, k, hash_id)!

	s := decrypt_with_check(priv, em)!
	return s
}

pub fn verify_x931(pubkey PublicKey, hasher IX931Hasher, hashed []u8, sig []u8) ! {
	hash_id := x931_hash_info(hasher, hashed.len)!

	k := pubkey.size()
	if k < hashed.len + 3 {
		return ErrVerification{}
	}

	if k != sig.len {
		return ErrVerification{}
	}

	em := encrypt(pubkey, sig)!

	emsa_x931_verify(hashed, em, k, hash_id)!
}

fn emsa_x931_encode(m_hash []u8, em_len int, hash_id int) ![]u8 {
	h_len := m_hash.len

	j := em_len - h_len - 3
	if j < 0 {
		return ErrMessageTooLong{}
	}

	mut em := []u8{len: em_len}
	em[0] = 0x6b
	for i := 1; i < j; i++ {
		em[i] = 0xbb
	}
	em[j] = 0xba

	copy(mut em[em_len - h_len - 2..], m_hash)
	em[em_len - 2] = u8(hash_id)
	em[em_len - 1] = 0xcc

	return em
}

fn emsa_x931_verify(m_hash []u8, em []u8, em_len int, hash_id int) ! {
	if em_len < 3 {
		return ErrVerification{}
	}

	h_len := m_hash.len
	j := em_len - h_len - 3

	mut ok := subtle.constant_time_byte_eq(em[0], 0x6b)
	ok &= subtle.constant_time_byte_eq(em[j], 0xba)
	ok &= subtle.constant_time_compare(em[em_len - h_len - 2..em_len - 2], m_hash)
	ok &= subtle.constant_time_byte_eq(em[em_len - 2], u8(hash_id))
	ok &= subtle.constant_time_byte_eq(em[em_len - 1], 0xcc)

	for i := 1; i < j; i++ {
		ok &= subtle.constant_time_byte_eq(em[i], 0xbb)
	}

	if ok != 1 {
		return ErrVerification{}
	}
}

fn x931_hash_info(hasher IX931Hasher, in_len int) !int {
	hash_id := hasher.hash_id()
	if hash_id == 0 {
		return 0
	}

	hash_len := hasher.hash_size()
	if in_len != hash_len {
		return error('v-rsa: input must be hashed message')
	}

	return hash_id
}
