module rsa

import hash
import rand
import math.big

// EMSA-PSS encoding (RFC 8017)
fn emsa_pss_encode(m_hash []u8, em_bits int, salt []u8, mut h hash.Hash) ![]u8 {
    h_len := h.size()
    s_len := salt.len
    em_len := (em_bits + 7) / 8

    if m_hash.len != h_len {
        return error('v-rsa: input must be hashed with given hash')
    }
    if em_len < h_len + s_len + 2 {
        return error('v-rsa: key size too small for PSS signature')
    }

    mut em := []u8{len: em_len}
    ps_len := em_len - s_len - h_len - 2

    mut db := []u8{len: ps_len+1+s_len}

    // H = Hash(0x00*8 || mHash || salt)
    mut prefix := [u8(0),0,0,0,0,0,0,0]

    h.reset()
    h.write(prefix)!
    h.write(m_hash)!
    h.write(salt)!
    h_hash := h.sum([])

	copy(mut em[ps_len+1+s_len .. em_len-1], h_hash)

    db[ps_len] = 0x01
	copy(mut db[ps_len+1..], salt)

    // dbMask = MGF1(h, em_len - h_len - 1)
    mgf1_xor(mut db, mut h, h_hash)!

    // zero leftmost bits
    db[0] &= 0xff >> (8*em_len - em_bits)
	copy(mut em[0..ps_len+1+s_len], db)

    em[em_len - 1] = 0xbc

    return em
}

// EMSA-PSS verify
fn emsa_pss_verify(m_hash []u8, em []u8, em_bits int, s_len_in int, mut h hash.Hash) ! {
    h_len := h.size()
	
    mut s_len := s_len_in
    if s_len == pss_salt_length_equals_hash {
        s_len = h_len
    }

    em_len := (em_bits + 7) / 8
    if em_len != em.len {
        return error('rsa: internal error: inconsistent length')
    }

    if h_len != m_hash.len {
        return error('v-rsa: verification error')
    }
    if em_len < h_len + s_len + 2 {
        return error('v-rsa: verification error')
    }
    if em[em_len - 1] != 0xbc {
        return error('v-rsa: verification error')
    }

    mut db := em[0..em_len - h_len - 1].clone()
    h_hash := em[em_len - h_len - 1 .. em_len - 1].clone()

    bit_mask := u8(0xff >> (8*em_len - em_bits))
    if em[0] & ~bit_mask != 0 {
        return error('v-rsa: verification error')
    }

    // dbMask = MGF(H)
    mgf1_xor(mut db, mut h, h_hash)!
    db[0] &= bit_mask

    if s_len == pss_salt_length_auto {
        ps_len := find_bytes_index(db, 0x01)
        if ps_len < 0 {
            return error('v-rsa: verification error')
        }

        s_len = db.len - ps_len - 1
    }

    ps_len := em_len - h_len - s_len - 2
    for i := 0; i < ps_len; i++ {
        if db[i] != 0x00 {
            return error('v-rsa: verification error')
        }
    }
    if db[ps_len] != 0x01 {
        return error('v-rsa: verification error')
    }

    salt := db[db.len - s_len .. ].clone()

    mut prefix := [u8(0),0,0,0,0,0,0,0]

    h.reset()
    h.write(prefix)!
    h.write(m_hash)!
    h.write(salt)!
    h0_hash := h.sum([])

    if h0_hash != h_hash {
        return error('v-rsa: verification error')
    }
}

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

@[params]
pub struct PSSOptions {
pub:
    salt_leng int
	hash      &hash.Hash = unsafe { nil }
}

pub fn (opts PSSOptions) hash_func() &hash.Hash {
	return opts.hash
}

pub fn (opts PSSOptions) salt_length() int {
    return opts.salt_leng
}

// SignPSS signs digest with PSS
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

// VerifyPSS verifies PSS signature
pub fn verify_pss(pubkey PublicKey, mut h hash.Hash, digest []u8, sig []u8, opts PSSOptions) ! {
    if sig.len != pubkey.size() {
        return error('v-rsa: verification error')
    }

    s := big.integer_from_bytes(sig)
    m := encrypt(pubkey, s)!

    em_bits := pubkey.n.bit_len() - 1
    em_len := (em_bits + 7) / 8
    if m.bit_len() > em_len * 8 {
        return error('v-rsa: verification error')
    }

    mut em := []u8{len: em_len}

    m_bytes, _ := m.bytes()
    copy(mut em[em_len - m_bytes.len ..], m_bytes)

    return emsa_pss_verify(digest, em, em_bits, opts.salt_length(), mut h)
}
