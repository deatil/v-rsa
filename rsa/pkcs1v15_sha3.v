module rsa

import crypto.sha3

fn new_sha3_224() &Sha3Digest {
	h := sha3.new224() or { panic(err) }

	mut d := &Sha3Digest{}
	d.hash = h
	d.hash_size = sha3.size_224
	d.hash_block_size = sha3.rate_224
	return d
}

fn new_sha3_256() &Sha3Digest {
	h := sha3.new256() or { panic(err) }

	mut d := &Sha3Digest{}
	d.hash = h
	d.hash_size = sha3.size_256
	d.hash_block_size = sha3.rate_256
	return d
}

fn new_sha3_384() &Sha3Digest {
	h := sha3.new384() or { panic(err) }

	mut d := &Sha3Digest{}
	d.hash = h
	d.hash_size = sha3.size_384
	d.hash_block_size = sha3.rate_384
	return d
}

fn new_sha3_512() &Sha3Digest {
	h := sha3.new512() or { panic(err) }

	mut d := &Sha3Digest{}
	d.hash = h
	d.hash_size = sha3.size_512
	d.hash_block_size = sha3.rate_512
	return d
}

interface ISha3Hasher {
mut:
	write(data []u8)!
	checksum() []u8
}

struct Sha3Digest {
mut:
	hash &ISha3Hasher = unsafe { nil }
	hash_size int
	hash_block_size int
}

pub fn (d &Sha3Digest) sum(b_in []u8) []u8 {
	mut h0 := d.hash
	hashed := h0.checksum()
	mut b_out := b_in.clone()
	b_out << hashed
	return b_out
}

pub fn (d &Sha3Digest) size() int {
	return d.hash_size
}

pub fn (d &Sha3Digest) block_size() int {
	return d.hash_block_size
}

pub fn (mut d Sha3Digest) free() {
}

pub fn (mut d Sha3Digest) reset() {
	d.hash = sha3.new_digest(d.hash_block_size, d.hash_size) or {
		panic(err)
	}
}

pub fn (mut d Sha3Digest) write(data []u8) !int {
	mut h0 := d.hash
	h0.write(data)!

	return data.len
}
