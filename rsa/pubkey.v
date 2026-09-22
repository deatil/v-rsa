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

	mut primes := []big.Integer{}
	primes << p
	primes << q

	if version == 1 {
		crts_seq := fields[9].into_object[asn1.Sequence]()!
		crts_fields := crts_seq.fields()

		for i := 0; i < crts_fields.len; i++ {
			crts_seq2 := crts_fields[i].into_object[asn1.Sequence]()!
			crts_fields2 := crts_seq2.fields()

			prime_int := crts_fields2[0].into_object[asn1.Integer]()!
			prime := big.integer_from_radix(prime_int.hex(), 16)!

			// crt_seq = [prime, exp, coeff]
			primes << prime
		}
	}

	mut prikey := PrivateKey{
		PublicKey: PublicKey{
			n: n
			e: int(e)
		}
		d:         d
		primes:    primes
	}

	prikey.precompute()!

	return prikey
}

pub fn make_prikey_pkcs1_der(prikey PrivateKey) ![]u8 {
	n := asn1.Integer.from_hex(prikey.n.hex())!
	e := asn1.Integer.from_int(prikey.e)
	d := asn1.Integer.from_hex(prikey.d.hex())!
	p := asn1.Integer.from_hex(prikey.primes[0].hex())!
	q := asn1.Integer.from_hex(prikey.primes[1].hex())!
	dp := asn1.Integer.from_hex(prikey.precomputed.dp.hex())!
	dq := asn1.Integer.from_hex(prikey.precomputed.dq.hex())!
	q_inv := asn1.Integer.from_hex(prikey.precomputed.q_inv.hex())!

	seq := asn1.Sequence{}

	if prikey.primes.len > 2 {
		version := asn1.Integer.from_int(1)
		seq.add_element(version)!
	} else {
		version := asn1.Integer.from_int(0)
		seq.add_element(version)!
	}
	seq.add_element(n)!
	seq.add_element(e)!
	seq.add_element(d)!
	seq.add_element(p)!
	seq.add_element(q)!
	seq.add_element(dp)!
	seq.add_element(dq)!
	seq.add_element(q_inv)!

	if prikey.primes.len > 2 {
		crts_seq := asn1.Sequence{}

		for i := 2; i < prikey.primes.len; i++ {
			prime := asn1.Integer.from_hex(prikey.primes[i].hex())!

			crt_value := prikey.precomputed.crt_values[i - 2]
			exp := asn1.Integer.from_hex(crt_value.exp.hex())!
			coeff := asn1.Integer.from_hex(crt_value.coeff.hex())!

			// crt_seq = [prime, exp, coeff]
			crt_seq := asn1.Sequence{}

			crt_seq.add_element(prime)!
			crt_seq.add_element(exp)!
			crt_seq.add_element(coeff)!

			crts_seq.add_element(crt_seq)!
		}

		seq.add_element(crts_seq)!
	}

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
