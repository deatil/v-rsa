module rsa

import math.big
import x.encoding.asn1

pub fn parse_prikey_pkcs1_der(bytes []u8) !PrivateKey {
	elem := asn1.decode(bytes)!
	assert elem.tag().equal(asn1.default_sequence_tag)

	seq := elem.into_object[asn1.Sequence]()!
	fields := seq.fields()

	if fields.len < 6 {
		return error('v-rsa: prikey der error')
	}

	version_int := fields[0].into_object[asn1.Integer]()!
	n_int := fields[1].into_object[asn1.Integer]()!
	e_int := fields[2].into_object[asn1.Integer]()!
	d_int := fields[3].into_object[asn1.Integer]()!
	p_int := fields[4].into_object[asn1.Integer]()!
	q_int := fields[5].into_object[asn1.Integer]()!

	version := version_int.as_i64()!
	if version != 0 && version != 1 {
		return error('v-rsa: RSA PKCS1 private key version is error')
	}

	n := big.integer_from_radix(n_int.hex(), 16)!
	e := e_int.as_i64()!
	d := big.integer_from_radix(d_int.hex(), 16)!
	p := big.integer_from_radix(p_int.hex(), 16)!
	q := big.integer_from_radix(q_int.hex(), 16)!

	mut prikey := PrivateKey{
		PublicKey: PublicKey{
			n: n
			e: int(e)
		}
		d:         d
		primes:    [p, q]
	}

	prikey.precompute()!

	return prikey
}

pub fn make_prikey_pkcs1_der(prikey PrivateKey) ![]u8 {
	version := asn1.Integer.from_int(0)
	n := asn1.Integer.from_hex(prikey.n.hex())!
	e := asn1.Integer.from_int(prikey.e)
	d := asn1.Integer.from_hex(prikey.d.hex())!
	p := asn1.Integer.from_hex(prikey.primes[0].hex())!
	q := asn1.Integer.from_hex(prikey.primes[1].hex())!

	seq := asn1.Sequence{}

	seq.add_element(version)!
	seq.add_element(n)!
	seq.add_element(e)!
	seq.add_element(d)!
	seq.add_element(p)!
	seq.add_element(q)!

	new_data := asn1.encode(seq)!

	return new_data
}

pub fn parse_pubkey_pkcs1_der(bytes []u8) !PublicKey {
	elem := asn1.decode(bytes)!
	assert elem.tag().equal(asn1.default_sequence_tag)

	seq := elem.into_object[asn1.Sequence]()!
	fields := seq.fields()

	if fields.len < 2 {
		return error('v-rsa: pubkey der error')
	}

	n_int := fields[0].into_object[asn1.Integer]()!
	e_int := fields[1].into_object[asn1.Integer]()!

	n := big.integer_from_radix(n_int.hex(), 16)!
	e := e_int.as_i64()!

	pubkey := PublicKey{
		n: n
		e: int(e)
	}

	return pubkey
}

pub fn make_pubkey_pkcs1_der(pubkey PublicKey) ![]u8 {
	n := asn1.Integer.from_hex(pubkey.n.hex())!
	e := asn1.Integer.from_int(pubkey.e)

	seq := asn1.Sequence{}

	seq.add_element(n)!
	seq.add_element(e)!

	new_data := asn1.encode(seq)!

	return new_data
}

// =====

pub fn parse_prikey_pkcs8_der(bytes []u8) !PrivateKey {
	elem := asn1.decode(bytes)!
	assert elem.tag().equal(asn1.default_sequence_tag)

	seq := elem.into_object[asn1.Sequence]()!
	fields := seq.fields()

	ver := fields[0].into_object[asn1.Integer]()!
	version := ver.as_i64()!
	if version != 0 && version != 1 {
		return error('v-rsa: RSA PKCS8 private key version is error')
	}

	oid_seq := fields[1].into_object[asn1.Sequence]()!
	oid_seq_fields := oid_seq.fields()

	oid := oid_seq_fields[0].into_object[asn1.ObjectIdentifier]()!
	check_pkcs8_publickey_oid(oid)!

	prikey_octet := fields[2].into_object[asn1.OctetString]()!
	prikey_octet_bytes := prikey_octet.payload()!

	prikey := parse_prikey_pkcs1_der(prikey_octet_bytes)!
	return prikey
}

pub fn make_prikey_pkcs8_der(prikey PrivateKey) ![]u8 {
	version := asn1.Integer.from_int(0)
	oid_rsa_publickey := asn1.ObjectIdentifier.new('1.2.840.113549.1.1.1')!
	null := asn1.Null{}
	prikey_data := make_prikey_pkcs1_der(prikey)!

	algo_seq := asn1.Sequence{}
	algo_seq.add_element(oid_rsa_publickey)!
	algo_seq.add_element(null)!

	prikey_data_octet := asn1.OctetString.new(prikey_data.bytestr())!

	seq := asn1.Sequence{}
	seq.add_element(version)!
	seq.add_element(algo_seq)!
	seq.add_element(prikey_data_octet)!
	new_data := asn1.encode(seq)!

	return new_data
}

pub fn parse_pubkey_pkcs8_der(bytes []u8) !PublicKey {
	elem := asn1.decode(bytes)!
	assert elem.tag().equal(asn1.default_sequence_tag)

	seq := elem.into_object[asn1.Sequence]()!
	fields := seq.fields()

	oid_seq := fields[0].into_object[asn1.Sequence]()!
	oid_fields := oid_seq.fields()

	oid := oid_fields[0].into_object[asn1.ObjectIdentifier]()!
	check_pkcs8_publickey_oid(oid)!

	pubkey_bitstring := fields[1].into_object[asn1.BitString]()!
	pubkey_bytes := pubkey_bitstring.data()

	pubkey := parse_pubkey_pkcs1_der(pubkey_bytes)!
	return pubkey
}

pub fn make_pubkey_pkcs8_der(pubkey PublicKey) ![]u8 {
	oid_rsa_publickey := asn1.ObjectIdentifier.new('1.2.840.113549.1.1.1')!
	null := asn1.Null{}
	pubkey_data := make_pubkey_pkcs1_der(pubkey)!

	algo_seq := asn1.Sequence{}
	algo_seq.add_element(oid_rsa_publickey)!
	algo_seq.add_element(null)!

	new_pubkey_data := make_bitstring_bytes(pubkey_data)
	pubkey_data_bitstring := asn1.BitString.new(new_pubkey_data.bytestr())!

	seq := asn1.Sequence{}
	seq.add_element(algo_seq)!
	seq.add_element(pubkey_data_bitstring)!
	new_data := asn1.encode(seq)!

	return new_data
}

fn make_bitstring_bytes(input []u8) []u8 {
	pad_len := if input.len % 8 == 0 { 0 } else { 8 - input.len % 8 }

	mut out := []u8{len: input.len + 2}

	out[0] = u8(pad_len)
	copy(mut out[1..], input)
	out[out.len - 1] = u8(0)

	return out
}

fn check_pkcs8_publickey_oid(oid asn1.ObjectIdentifier) ! {
	oid_rsa_publickey := asn1.ObjectIdentifier.new('1.2.840.113549.1.1.1')!
	if !oid_rsa_publickey.equal(oid) {
		return error('v-rsa: rsa oid error')
	}
}
