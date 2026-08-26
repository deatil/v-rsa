module rsa

import hash
import rand
import math.big

// Per RFC 8017, Section 9.1
//
//     EM = MGF1 xor DB || H( 8*0x00 || mHash || salt ) || 0xbc
//
// where
//
//     DB = PS || 0x01 || salt
//
// and PS can be empty so
//
//     emLen = dbLen + hLen + 1 = psLen + sLen + hLen + 2
//

// EMSA-PSS encoding (RFC 8017)
fn emsa_pss_encode(m_hash []u8, em_bits int, salt []u8, mut h hash.Hash) ![]u8 {
	// See RFC 8017, Section 9.1.1.

    h_len := h.size()
    s_len := salt.len
    em_len := (em_bits + 7) / 8

	// 1.  If the length of M is greater than the input limitation for the
	//     hash function (2^61 - 1 octets for SHA-1), output "message too
	//     long" and stop.
	//
	// 2.  Let mHash = Hash(M), an octet string of length hLen.

    if m_hash.len != h_len {
        return error('v-rsa: input must be hashed with given hash')
    }

	// 3.  If emLen < hLen + sLen + 2, output "encoding error" and stop.

    if em_len < h_len + s_len + 2 {
        return error('v-rsa: key size too small for PSS signature')
    }

    mut em := []u8{len: em_len}
    ps_len := em_len - s_len - h_len - 2

    mut db := []u8{len: ps_len+1+s_len}

	// 4.  Generate a random octet string salt of length sLen; if sLen = 0,
	//     then salt is the empty string.
	//
	// 5.  Let
	//       M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt;
	//
	//     M' is an octet string of length 8 + hLen + sLen with eight
	//     initial zero octets.
	//
	// 6.  Let H = Hash(M'), an octet string of length hLen.

    // H = Hash(0x00*8 || mHash || salt)
    mut prefix := [u8(0),0,0,0,0,0,0,0]

    h.reset()
    h.write(prefix)!
    h.write(m_hash)!
    h.write(salt)!
    h_hash := h.sum([])

	copy(mut em[ps_len+1+s_len .. em_len-1], h_hash)

	// 7.  Generate an octet string PS consisting of emLen - sLen - hLen - 2
	//     zero octets. The length of PS may be 0.
	//
	// 8.  Let DB = PS || 0x01 || salt; DB is an octet string of length
	//     emLen - hLen - 1.

    db[ps_len] = 0x01
	copy(mut db[ps_len+1..], salt)

	// 9.  Let dbMask = MGF(H, emLen - hLen - 1).
	//
	// 10. Let maskedDB = DB \xor dbMask.

    // dbMask = MGF1(h, em_len - h_len - 1)
    mgf1_xor(mut db, mut h, h_hash)!

	// 11. Set the leftmost 8 * emLen - emBits bits of the leftmost octet in
	//     maskedDB to zero.

    db[0] &= 0xff >> (8*em_len - em_bits)
	copy(mut em[0..ps_len+1+s_len], db)

	// 12. Let EM = maskedDB || H || 0xbc.
    em[em_len - 1] = 0xbc

    return em
}

// EMSA-PSS verify
fn emsa_pss_verify(m_hash []u8, em []u8, em_bits int, s_len_in int, mut h hash.Hash) ! {
	// See RFC 8017, Section 9.1.2.

    h_len := h.size()
	
    mut s_len := s_len_in
    if s_len == pss_salt_length_equals_hash {
        s_len = h_len
    }

    em_len := (em_bits + 7) / 8
    if em_len != em.len {
        return error('v-rsa: internal error: inconsistent length')
    }

	// 1.  If the length of M is greater than the input limitation for the
	//     hash function (2^61 - 1 octets for SHA-1), output "inconsistent"
	//     and stop.
	//
	// 2.  Let mHash = Hash(M), an octet string of length hLen.
    if h_len != m_hash.len {
        return ErrVerification{}
    }

	// 3.  If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    if em_len < h_len + s_len + 2 {
        return ErrVerification{}
    }

	// 4.  If the rightmost octet of EM does not have hexadecimal value
	//     0xbc, output "inconsistent" and stop.
    if em[em_len - 1] != 0xbc {
        return ErrVerification{}
    }

	// 5.  Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and
	//     let H be the next hLen octets.
    mut db := em[0..em_len - h_len - 1].clone()
    h_hash := em[em_len - h_len - 1 .. em_len - 1].clone()

	// 6.  If the leftmost 8 * emLen - emBits bits of the leftmost octet in
	//     maskedDB are not all equal to zero, output "inconsistent" and
	//     stop.
    bit_mask := u8(0xff >> (8*em_len - em_bits))
    if em[0] & ~bit_mask != 0 {
        return ErrVerification{}
    }

	// 7.  Let dbMask = MGF(H, emLen - hLen - 1).
	//
	// 8.  Let DB = maskedDB \xor dbMask.
    mgf1_xor(mut db, mut h, h_hash)!

	// 9.  Set the leftmost 8 * emLen - emBits bits of the leftmost octet in DB
	//     to zero.
    db[0] &= bit_mask

	// If we don't know the salt length, look for the 0x01 delimiter.
    if s_len == pss_salt_length_auto {
        ps_len := find_bytes_index(db, 0x01)
        if ps_len < 0 {
            return ErrVerification{}
        }

        s_len = db.len - ps_len - 1
    }

	// 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero
	//     or if the octet at position emLen - hLen - sLen - 1 (the leftmost
	//     position is "position 1") does not have hexadecimal value 0x01,
	//     output "inconsistent" and stop.
    ps_len := em_len - h_len - s_len - 2
    for i := 0; i < ps_len; i++ {
        if db[i] != 0x00 {
            return ErrVerification{}
        }
    }
    if db[ps_len] != 0x01 {
        return ErrVerification{}
    }

	// 11.  Let salt be the last sLen octets of DB.
    salt := db[db.len - s_len .. ].clone()

	// 12.  Let
	//          M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ;
	//     M' is an octet string of length 8 + hLen + sLen with eight
	//     initial zero octets.
	//
	// 13. Let H' = Hash(M'), an octet string of length hLen.

    mut prefix := [u8(0),0,0,0,0,0,0,0]

    h.reset()
    h.write(prefix)!
    h.write(m_hash)!
    h.write(salt)!
    h0_hash := h.sum([])

	// 14. If H = H', output "consistent." Otherwise, output "inconsistent."
    if h0_hash != h_hash {
        return ErrVerification{}
    }
}

// signPSSWithSalt calculates the signature of hashed using PSS with specified salt.
// Note that hashed must be the result of hashing the input message using the
// given hash function. salt is a random sequence of bytes whose length will be
// later used to verify the signature.
fn sign_pss_with_salt(priv PrivateKey, mut h hash.Hash, hashed []u8, salt []u8) ![]u8 {
	em_bits := priv.n.bit_len() - 1
    em := emsa_pss_encode(hashed, em_bits, salt, mut h)!

    m := big.integer_from_bytes(em)
    c := decrypt_and_check(priv, m)!

    mut s := []u8{len: priv.size()}

    c_bytes, _ := c.bytes()
    copy(mut s[s.len - c_bytes.len ..], c_bytes)

    return s
}

// pss_salt_length_auto causes the salt in a PSS signature to be as large
// as possible when signing, and to be auto-detected when verifying.
pub const pss_salt_length_auto = 0
// pss_salt_length_equals_hash causes the salt length to equal the length
// of the hash used in the signature.
pub const pss_salt_length_equals_hash = -1

// PSSOptions contains options for creating and verifying PSS signatures.
@[params]
pub struct PSSOptions {
pub:
	// SaltLength controls the length of the salt used in the PSS
	// signature. It can either be a number of bytes, or one of the special
	// pss_salt_length constants.
    salt_leng int

	// hash is the hash function used to generate the message digest. If not
	// zero, it overrides the hash function passed to SignPSS.
	hash &hash.Hash = unsafe { nil }
}

// hash_func returns opts.hash.
pub fn (opts PSSOptions) hash_func() &hash.Hash {
	return opts.hash
}

pub fn (opts PSSOptions) salt_length() int {
    return opts.salt_leng
}

// sign_pss calculates the signature of digest using PSS.
//
// digest must be the result of hashing the input message using the given hash
// function. The opts argument may be nil, in which case sensible defaults are
// used. If opts.hash is set, it overrides hash.
pub fn sign_pss(mut random rand.PRNG, priv PrivateKey, mut h hash.Hash, digest []u8, opts PSSOptions) ![]u8 {
    mut hasher := h
    if opts.hash != unsafe { nil } {
        hasher = hash.Hash(opts.hash)
    }

    mut salt_len := opts.salt_length()
    match salt_len {
        pss_salt_length_auto {
            salt_len = (priv.n.bit_len() - 1 + 7) / 8 - 2 - hasher.size()
        }
        pss_salt_length_equals_hash {
            salt_len = hasher.size()
        }
		else {}
    }

    mut salt := []u8{len: salt_len}
    rand_read_full(mut random, mut salt)

    return sign_pss_with_salt(priv, mut hasher, digest, salt)
}

// verify_pss verifies a PSS signature.
//
// A valid signature is indicated by returning a nil error. digest must be the
// result of hashing the input message using the given hash function. The opts
// argument may be nil, in which case sensible defaults are used. opts.hash is
// ignored.
pub fn verify_pss(pubkey PublicKey, mut h hash.Hash, digest []u8, sig []u8, opts PSSOptions) ! {
    if sig.len != pubkey.size() {
        return ErrVerification{}
    }

    s := big.integer_from_bytes(sig)
    m := encrypt(pubkey, s)!

    em_bits := pubkey.n.bit_len() - 1
    em_len := (em_bits + 7) / 8
    if m.bit_len() > em_len * 8 {
        return ErrVerification{}
    }

    mut em := []u8{len: em_len}

    m_bytes, _ := m.bytes()
    copy(mut em[em_len - m_bytes.len ..], m_bytes)

    return emsa_pss_verify(digest, em, em_bits, opts.salt_length(), mut h)
}
