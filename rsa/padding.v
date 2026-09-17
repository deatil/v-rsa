module rsa

import rand
import subtle

fn rsa_pkcs1_type_1_pad(em_len int, msg []u8) ![]u8 {
	if msg.len > em_len - 11 {
		return ErrMessageTooLong{}
	}

	mut em := []u8{len: em_len}
	em[1] = 1

	for i := 2; i < em_len - msg.len - 1; i++ {
		em[i] = 0xff
	}

	em[em.len - msg.len - 1] = 0
	copy(mut em[em.len - msg.len..], msg)

	return em
}

fn rsa_pkcs1_type_1_unpad(k int, em []u8) ![]u8 {
	if k < 11 {
		return ErrDecryption{}
	}

	if em[0] != 0 || (em[1] != 0 && em[1] != 1) {
		return error('v-rsa: Invalid header')
	}

	mut i := 2
	for i < em.len {
		if em[i] != 0xff {
			if em[i] == 0 {
				break
			}
		}

		i += 1
	}

	i += 1

	if i == em.len {
		return []
	}

	if i - 1 < 8 {
		return error('v-rsa: Inconsistent')
	}

	return em[i..]
}

fn rsa_pkcs1_type_2_pad(mut random rand.PRNG, em_len int, msg []u8) ![]u8 {
	if msg.len > em_len - 11 {
		return ErrMessageTooLong{}
	}

	// EM = 0x00 || 0x02 || PS || 0x00 || M
	mut em := []u8{len: em_len}
	em[1] = 2

	mut ps := []u8{len: (em.len - msg.len - 3)}
	mut mm := []u8{len: msg.len}

	non_zero_random_bytes(mut ps, mut random)

	em[em.len - msg.len - 1] = 0

	copy(mut mm, msg)

	copy(mut em[2..(em.len - msg.len - 1)], ps)
	copy(mut em[(em.len - msg.len)..], mm)

	return em
}

fn rsa_pkcs1_type_2_unpad(k int, em []u8) ![]u8 {
	if k < 11 {
		return ErrDecryption{}
	}

	valid, out, index := rsa_pkcs1_type_2_unpad_internal(em)!
	if valid == 0 {
		return ErrDecryption{}
	}

	return out[index..]
}

fn rsa_pkcs1_type_2_unpad_internal(em []u8) !(int, []u8, int) {
	first_byte_zero := subtle.constant_time_byte_eq(em[0], 0)
	second_byte_two := subtle.constant_time_byte_eq(em[1], 2)

	// The remainder of the plaintext must be a string of non-zero random
	// octets, followed by a 0, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the zero.
	//   index: the offset of the first zero byte.
	mut looking_for_index := 1

	mut index := 0
	for i := 2; i < em.len; i++ {
		equals0 := subtle.constant_time_byte_eq(em[i], 0)

		index = subtle.constant_time_select(looking_for_index & equals0, i, index)
		looking_for_index = subtle.constant_time_select(equals0, 0, looking_for_index)
	}

	// The PS padding must be at least 8 bytes long, and it starts two
	// bytes into em.
	valid_ps := subtle.constant_time_less_or_eq(2 + 8, index)

	valid := first_byte_zero & second_byte_two & (~looking_for_index & 1) & valid_ps
	real_index := subtle.constant_time_select(valid, index + 1, 0)

	return valid, em, real_index
}

fn rsa_x931_pad(em_len int, msg []u8) ![]u8 {
	mut em := []u8{len: em_len}

	j := em_len - msg.len - 2
	if j < 0 {
		return error('v-rsa: Msg too large')
	}

	if j == 0 {
		em[0] = 0x6a
	} else {
		em[0] = 0x6b
		if j > 1 {
			for i := 1; i < j; i++ {
				em[i] = 0xbb
			}
		}
		em[j] = 0xba
	}

	copy(mut em[em.len - msg.len - 1..], msg)
	em[em.len - 1] = 0xcc

	return em
}

fn rsa_x931_unpad(k int, em []u8) ![]u8 {
	if k < 2 {
		return ErrDecryption{}
	}

	mut i := 0
	mut j := 0

	if em[0] != 0x6a && em[0] != 0x6b {
		return error('v-rsa: Invalid Header')
	}

	if em[0] == 0x6b {
		j = em.len - 3

		i = 0
		for ; i < j; i += 1 {
			if em[i + 1] == 0xba {
				break
			}

			if em[i + 1] != 0xbb {
				return error('v-rsa: Invalid Padding')
			}
		}

		j -= i
	} else {
		j = em.len - 2
	}

	if em[em.len - 1] != 0xcc {
		return error('v-rsa: Invalid Trailer')
	}

	return em[em.len - j - 1..em.len - 1]
}

fn rsa_no_pad(em_len int, msg []u8) ![]u8 {
	if msg.len > em_len {
		return error('v-rsa: Msg Too Large For Key Size')
	}
	if msg.len < em_len {
		return error('v-rsa: Msg Too Small For Key Size')
	}

	return msg
}

fn rsa_no_unpad(k int, em []u8) ![]u8 {
	if em.len != k {
		return ErrDecryption{}
	}

	return em
}
