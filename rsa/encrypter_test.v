module rsa

import rand.seed
import rand.mt19937
import crypto.pem
import encoding.hex
import encoding.base64

fn from_hex(str string) ![]u8 {
	bytes := hex.decode(str)!
	return bytes
}

fn get_rng() &mt19937.MT19937RNG {
	seed_data := seed.time_seed_array(2)

	mut rnd := &mt19937.MT19937RNG{}
	rnd.seed(seed_data)

	return rnd
}

fn get_prikey3() !PrivateKey {
	key_der := 'MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu/ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWuRTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7AIU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlStAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V'
	key_str := base64.url_decode_str(key_der)

	mut prikey := parse_prikey_pkcs1_der(key_str.bytes())!
	prikey.precompute()!

	return prikey
}

fn get_prikey31() !PrivateKey {
	prikey_pem := '-----BEGIN RSA PRIVATE KEY-----
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
7SEsFcPwusoU1g==
-----END RSA PRIVATE KEY-----'

	block1, _ := pem.decode(prikey_pem) or { pem.Block{}, '' }

	prikey := parse_prikey_pkcs1_der(block1.data)!

	return prikey
}

fn test_encrypt_privatekey_with_opts() {
	prikey := get_prikey3()!
	pubkey := prikey.public()

	msg := '12345678abcde'.bytes()

	{
		mut encrypter := Encrypter.new()

		ciphertext := encrypter.encrypt_privatekey(prikey, msg)!
		assert ciphertext.len > 0

		demsg := encrypter.decrypt_publickey(pubkey, ciphertext)!
		assert demsg.len > 0
		assert '12345678abcde' == demsg.bytestr()
	}
	{
		mut encrypter := Encrypter.new()

		ciphertext := '7b1783ab067d84749b14f4da0fe63467a16c087ac1edf552387665e73047ebd1cc881fc064b5b2e427ceebefd50616f9ada687c828416e44bdaf29ed07d62551'
		ct := from_hex(ciphertext)!

		demsg := encrypter.decrypt_publickey(pubkey, ct)!
		assert demsg.len > 0
		assert 'rsa PKCS1-v1_5 encrypt and decrypt' == demsg.bytestr()
	}

	{
		mut encrypter := Encrypter.new()
		encrypter.with_padding(.x931_padding)

		ciphertext := encrypter.encrypt_privatekey(prikey, msg)!
		assert ciphertext.len > 0

		demsg := encrypter.decrypt_publickey(pubkey, ciphertext)!
		assert demsg.len > 0
		assert '12345678abcde' == demsg.bytestr()
	}
	{
		ciphertext := '3a120a22e2ff5891ae0e04c71c15de4e23feb8209aebb340603384d451c36817096e5af7d4ae63be4952dd89f241d41a5267dbc027adcd3b7db18c563d3d6116'
		ct := from_hex(ciphertext)!

		mut encrypter := Encrypter.new()
		encrypter.with_padding(.x931_padding)

		demsg := encrypter.decrypt_publickey(pubkey, ct)!
		assert demsg.len > 0
		assert '12345678abcde' == demsg.bytestr()
	}

	msg2 := 'rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and dec'.bytes()

	{
		mut encrypter := Encrypter.new()
		encrypter.with_padding(.no_padding)

		ciphertext := encrypter.encrypt_privatekey(prikey, msg2)!
		assert ciphertext.len > 0

		demsg := encrypter.decrypt_publickey(pubkey, ciphertext)!
		assert demsg.len > 0
		assert msg2.bytestr() == demsg.bytestr()
	}
	{
		ciphertext := '397f0d2b34463c22dee6fb11edcb881d0c0a9d8ba5bb1587cf259ce5d177c7769b5776927be17c687650602a79c0f45317d85010676b90444f27de51b01725a7'
		ct := from_hex(ciphertext)!

		mut encrypter := Encrypter.new()
		encrypter.with_padding(.no_padding)

		demsg := encrypter.decrypt_publickey(pubkey, ct)!
		assert demsg.len > 0
		assert msg2.bytestr() == demsg.bytestr()
	}

	{
		msg3 := 'rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt andd'.bytes()

		mut encrypter := Encrypter.new()
		encrypter.with_padding(.x931_padding)

		ciphertext := encrypter.encrypt_privatekey(prikey, msg3)!
		assert ciphertext.len > 0

		demsg := encrypter.decrypt_publickey(pubkey, ciphertext)!
		assert demsg.len > 0
		assert msg3.bytestr() == demsg.bytestr()
	}
	{
		msg3 := 'rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and d'.bytes()

		mut encrypter := Encrypter.new()
		encrypter.with_padding(.x931_padding)

		ciphertext := encrypter.encrypt_privatekey(prikey, msg3)!
		assert ciphertext.len > 0

		demsg := encrypter.decrypt_publickey(pubkey, ciphertext)!
		assert demsg.len > 0
		assert msg3.bytestr() == demsg.bytestr()
	}
}

fn test_encrypt_privatekey_with_opts_key() {
	prikey := get_prikey31()!
	pubkey := prikey.public()

	msg := '12345678abcde'.bytes()

	{
		mut encrypter := Encrypter.new()

		ciphertext := encrypter.encrypt_privatekey(prikey, msg)!
		assert ciphertext.len > 0

		demsg := encrypter.decrypt_publickey(pubkey, ciphertext)!
		assert demsg.len > 0
		assert '12345678abcde' == demsg.bytestr()
	}
}

fn test_encrypt_with_opts() {
	prikey := get_prikey3()!
	pubkey := prikey.public()

	mut rng := get_rng()

	msg := '12345678abcde'.bytes()

	{
		mut encrypter := Encrypter.new()
		encrypter.with_random(mut rng)

		ciphertext := encrypter.encrypt(pubkey, msg)!
		assert ciphertext.len > 0

		demsg := encrypter.decrypt(prikey, ciphertext)!
		assert demsg.len > 0
		assert '12345678abcde' == demsg.bytestr()
	}
	{
		ciphertext := '24d17d224f3181383660c4e7d3d4092cc9f7fb015b344aa24afb90e1979fdfc35e7561b1fe217eb18371bf84a8b54e27b043d7b2f69d0418d6621ff0ab10c484'
		ct := from_hex(ciphertext)!

		mut encrypter := Encrypter.new()

		demsg := encrypter.decrypt(prikey, ct)!
		assert demsg.len > 0
		assert 'rsa PKCS1-v1_5 encrypt and decrypt' == demsg.bytestr()
	}

	msg2 := 'rsa PKCS1-v1_5 encrypt and decryptrsa PKCS1-v1_5 encrypt and dec'.bytes()

	{
		mut encrypter := Encrypter.new()
		encrypter.with_random(mut rng)
		encrypter.with_padding(.no_padding)

		ciphertext := encrypter.encrypt(pubkey, msg2)!
		assert ciphertext.len > 0

		demsg := encrypter.decrypt(prikey, ciphertext)!
		assert demsg.len > 0
		assert msg2.bytestr() == demsg.bytestr()
	}
	{
		ciphertext := '2994d74cb93e57f170f964f8401388b42ba904478a2bba2f0839a313f4a067da998003a99a0f8d7957577e86b220aa0536cbb77c0a53b535140e585a6089ca65'
		ct := from_hex(ciphertext)!

		mut encrypter := Encrypter.new()
		encrypter.with_padding(.no_padding)

		demsg := encrypter.decrypt(prikey, ct)!
		assert demsg.len > 0
		assert msg2.bytestr() == demsg.bytestr()
	}
}

fn get_prikey32() !PrivateKey {
	prikey_pem := '-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCXkhwdfZkthwkHIjrS6RQHx5QQz99uV6NbnNds/WyKlUDfVoh6
lVcT85qrqKNLmiC1ThgYkJz4IspZwxiPNbT5fXEJ5VYi30h+61Nu4kgSYPXGbAcV
mF5XcIcaFgCMh8Is2a0mtDBvv+34Wo8fClWwzeRuf1ghjvxw7Ps0WG2HpwIDAQAB
AoGAe2bEpynzxUJUkk9HDyIeYbsWjJ2BbkfBwzutlJm7fhTILU05bnwZ2i+SNMHm
uQ2yJYqASberZMaGcpBJdYcnYFwD7gCuoXxQokoM/AXzCljlcsUTcZLhhz820TQI
/ZIZ5wmojqW/+08h1rGg5zTgWc0k0Vz3HxIpDDIpAneN7VkCQQDGLQVu+GdvkUZ5
Oky81y9BBRDNQ1qRv4rghDnJckYK2nrH8mb81Abc2jl5u3CCu2P5D7gu+cDw8OUZ
hSos236zAkEAw8vdQFCpdr09KdwwwsluNKxAD2rlFlU1bkvZi1qqoiiDn4hSYYJ4
j6VwSDVi6pNJhLo8Li08yRdN12FFgynNPQJAGeJng0cOu5POEKd8vm2cznFK8ISL
n93U1d5vbdBvNZuzzcnribpn6xDV0QCagXjYZf+XnwsgGFhelCbAi3tf4QJAdKib
Ax8MWXsXXkGbq/NofmnDIWyHYm8Sjs0SqT00Pbn18q++peqe+reP1vY4IZvwSezM
vpaliQshjhqe2C+n4QJAOG1YEz/6HO1WENJSrCYm052XY6WUYWovpoQK7H+s7hjs
337p1vYdte9DzX7KlWAVjLvW94SPQ4+rfAiseKG7zQ==
-----END RSA PRIVATE KEY-----'

	block1, _ := pem.decode(prikey_pem) or { pem.Block{}, '' }
	prikey := parse_prikey_pkcs1_der(block1.data)!

	return prikey
}

fn test_encrypt_privatekey_with_opts_x931_check() {
	prikey := get_prikey32()!
	pubkey := prikey.public()

	msg := 'Hello RSA X9.31'

	ciphertext := '2B576194CCA758B99DE32BB18CEACB77D0EB4AA04E7B44153265F6E812A8F63B2F97F1F06121CEECE7B5B45B22869F067F73D7D97504E2F625324E4127350F711864B6A305F08A50F86FFC0DC52A677A0E9742431193E6F9AB33813390EB403ED8768E14EB237CE15921572BE5870E777468D743032E41DE7FC681EDC1D0824B'
	ct := from_hex(ciphertext)!

	mut encrypter := Encrypter.new()
	encrypter.with_padding(.x931_padding)

	demsg := encrypter.decrypt_publickey(pubkey, ct)!
	assert demsg.len > 0
	assert msg == demsg.bytestr()
}
