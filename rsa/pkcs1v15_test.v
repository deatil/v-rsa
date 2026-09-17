module rsa

import rand.seed
import rand.mt19937
import math.big
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

fn get_prikey() !PrivateKey {
	n := big.integer_from_radix('9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767', 16)!
	e := big.integer_from_radix('010001', 16)!
	d := big.integer_from_radix('63d392db30747f975f948ddd0e4205a43d743e8b775a1a670a55673b087ca0f0a7c1edc9ed97d5ffd852a02c53109a95ac4feff9f4ce38c7f7109939e99ac98b746ebde3faa182d07e73e754955da8cfb1f44f6e66363bbb0436c0b331e58d9d6a1c45ee3543f75e57d3aba8a89edf6a602235a01fa3afbce49b9632159faa70b570ac22d54af63e1c2f09869d91a0a4cbe4f2f4f0ba6c7469df09a1a121b7044df20b0e90089ae1e4d194bd72c85ead2db6de51b69961b0454b2ed3ac0ed9c1cd75dac818a6cb2d47ec0d950907ad14d68812b4ec83766795369c81fa10eab57c9774bf83f2d9eebc5f96c58d0a864bf005b905cf26deda7c5220754e2ee2b9', 16)!
	p := big.integer_from_radix('cc558bc7e22c34a9b5012f75ed39ccb284f2f4a64af78652b5cb6f77999202344161192ae63a5cd048d1943b80b98a66e15142187efc2d471f0f7d258843790d87b190a2a522a299b3b8ccf1d250b3003394d29ff6a9a79bbf9b08219d45969147dad74b44ad223adbebf48a2a0dd9ad394a8838fc8bbadc7025001663e4b46b', 16)!
	q := big.integer_from_radix('c4c5b893ac7215a18383cba6b27bb4e0f8a7890649da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5', 16)!

	mut prikey := PrivateKey{
		PublicKey: PublicKey{
			n: n
			e: e.int()
		}
		d:         d
		primes:    [p, q]
	}

	prikey.precompute()!

	return prikey
}

fn get_prikey2() !PrivateKey {
	n := big.integer_from_radix('9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767', 16)!
	e := big.integer_from_radix('010001', 16)!
	d := big.integer_from_radix('63d392db30747f975f948ddd0e4205a43d743e8b775a1a670a55673b087ca0f0a7c1edc9ed97d5ffd852a02c53109a95ac4feff9f4ce38c7f7109939e99ac98b746ebde3faa182d07e73e754955da8cfb1f44f6e66363bbb0436c0b331e58d9d6a1c45ee3543f75e57d3aba8a89edf6a602235a01fa3afbce49b9632159faa70b570ac22d54af63e1c2f09869d91a0a4cbe4f2f4f0ba6c7469df09a1a121b7044df20b0e90089ae1e4d194bd72c85ead2db6de51b69961b0454b2ed3ac0ed9c1cd75dac818a6cb2d47ec0d950907ad14d68812b4ec83766795369c81fa10eab57c9774bf83f2d9eebc5f96c58d0a864bf005b905cf26deda7c5220754e2ee2b9', 16)!
	p := big.integer_from_radix('cc558bc7e22c34a9b5012f75ed39ccb284f2f4a64af78652b5cb6f77999202344161192ae63a5cd048d1943b80b98a66e15142187efc2d471f0f7d258843790d87b190a2a522a299b3b8ccf1d250b3003394d29ff6a9a79bbf9b08219d45969147dad74b44ad223adbebf48a2a0dd9ad394a8838fc8bbadc7025001663e4b46b', 16)!
	q := big.integer_from_radix('c4c5b893ac7215a18383cba6b27bb4e0f8a7890649da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5', 16)!

	mut prikey := PrivateKey{
		PublicKey: PublicKey{
			n: n
			e: e.int()
		}
		d:         d
		primes:    [p, q]
	}

	return prikey
}

fn get_prikey3() !PrivateKey {
	key_der := "MIIBOgIBAAJBALKZD0nEffqM1ACuak0bijtqE2QrI/KLADv7l3kK3ppMyCuLKoF0fd7Ai2KW5ToIwzFofvJcS/STa6HA5gQenRUCAwEAAQJBAIq9amn00aS0h/CrjXqu/ThglAXJmZhOMPVn4eiu7/ROixi9sex436MaVeMqSNf7Ex9a8fRNfWss7Sqd9eWuRTUCIQDasvGASLqmjeffBNLTXV2A5g4t+kLVCpsEIZAycV5GswIhANEPLmax0ME/EO+ZJ79TJKN5yiGBRsv5yvx5UiHxajEXAiAhAol5N4EUyq6I9w1rYdhPMGpLfk7AIU2snfRJ6Nq2CQIgFrPsWRCkV+gOYcajD17rEqmuLrdIRexpg8N1DOSXoJ8CIGlStAboUGBxTDq3ZroNism3DaMIbKPyYrAqhKov1h5V"
	key_str := base64.url_decode_str(key_der)
    
    mut prikey := parse_prikey_pkcs1_der(key_str.bytes())!
    prikey.precompute()!

	return prikey
}

fn get_prikey31() !PrivateKey {
	prikey_pem := "-----BEGIN RSA PRIVATE KEY-----
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
7SEsFcPwusoU1g==
-----END RSA PRIVATE KEY-----"

	block1, _ := pem.decode(prikey_pem) or {pem.Block{}, ""}

	prikey := parse_prikey_pkcs1_der(block1.data)!

	return prikey
}

fn test_encrypt_pkcs1v15() {
	prikey := get_prikey()!
	pubkey := prikey.public()

	mut rng := get_rng()

	msg := '12345678abcde'.bytes()

	ciphertext := encrypt_pkcs1v15(mut rng, pubkey, msg)!
	assert ciphertext.len > 0

	demsg := decrypt_pkcs1v15(prikey, ciphertext)!
	assert demsg.len > 0
	assert '12345678abcde' == demsg.bytestr()
}

fn test_encrypt_pkcs1v15_no_precompute() {
	prikey := get_prikey2()!
	pubkey := prikey.public()

	mut rng := get_rng()

	msg := '12345678abcde'.bytes()

	assert 0 == prikey.precomputed.dp.int()

	ciphertext := encrypt_pkcs1v15(mut rng, pubkey, msg)!
	assert ciphertext.len > 0

	demsg := decrypt_pkcs1v15(prikey, ciphertext)!
	assert demsg.len > 0
	assert '12345678abcde' == demsg.bytestr()
}

fn test_decrypt_pkcs1v15_check() {
	prikey := get_prikey()!

	msg := '12345678abcde'.bytes()
	ciphertext := '24cb659f249d437efb94652b840e09c7124a1d9db2737d38979ac534cb038fd01c35fb1619fec7eaa2424c0c90f2827dc45ea925f9cd79607e4270895ef9f8142055ad2009fe273626c481df5835c96e0c4838b7bda3e45336b381434cbec1acd5f4480d61a08c2c304e773c03b8171c2c6f0aae8e07a8f600c688e6126ca69a99a9166cfa67ec61791b84f1966892ab3ff6f853d7482a83c7b25a35a4837f370d3f9fa6b523cd3734299ab5b400d2b2d15b20747f4384acd4749334e14835f691e5f4e3ca41cfdf269f486818f53f7a874ad7b366fdb23dbc840a8ebc504a1488280dfb1041ff461825b6da794d60efc8844312030c590cf414fa1c93008115'
	ct := from_hex(ciphertext)!

	demsg := decrypt_pkcs1v15(prikey, ct)!
	assert demsg.len > 0
	assert '12345678abcde' == demsg.bytestr()
}

fn test_decrypt_pkcs1v15_session_key_check() {
	prikey := get_prikey()!

	msg := '12345678abcde'.bytes()
	ciphertext := '24cb659f249d437efb94652b840e09c7124a1d9db2737d38979ac534cb038fd01c35fb1619fec7eaa2424c0c90f2827dc45ea925f9cd79607e4270895ef9f8142055ad2009fe273626c481df5835c96e0c4838b7bda3e45336b381434cbec1acd5f4480d61a08c2c304e773c03b8171c2c6f0aae8e07a8f600c688e6126ca69a99a9166cfa67ec61791b84f1966892ab3ff6f853d7482a83c7b25a35a4837f370d3f9fa6b523cd3734299ab5b400d2b2d15b20747f4384acd4749334e14835f691e5f4e3ca41cfdf269f486818f53f7a874ad7b366fdb23dbc840a8ebc504a1488280dfb1041ff461825b6da794d60efc8844312030c590cf414fa1c93008115'
	ct := from_hex(ciphertext)!

	mut key := []u8{len: msg.len}
	decrypt_pkcs1v15_session_key(prikey, ct, mut key)!

	assert key.len > 0
	assert '12345678abcde' == key.bytestr()
}

fn test_decrypt_pkcs1v15_session_key_with_opts_check() {
	prikey := get_prikey()!

	msg := '12345678abcde'.bytes()
	ciphertext := '24cb659f249d437efb94652b840e09c7124a1d9db2737d38979ac534cb038fd01c35fb1619fec7eaa2424c0c90f2827dc45ea925f9cd79607e4270895ef9f8142055ad2009fe273626c481df5835c96e0c4838b7bda3e45336b381434cbec1acd5f4480d61a08c2c304e773c03b8171c2c6f0aae8e07a8f600c688e6126ca69a99a9166cfa67ec61791b84f1966892ab3ff6f853d7482a83c7b25a35a4837f370d3f9fa6b523cd3734299ab5b400d2b2d15b20747f4384acd4749334e14835f691e5f4e3ca41cfdf269f486818f53f7a874ad7b366fdb23dbc840a8ebc504a1488280dfb1041ff461825b6da794d60efc8844312030c590cf414fa1c93008115'
	ct := from_hex(ciphertext)!

	mut rng := get_rng()

	key := decrypt_pkcs1v15_session_key_with_opts(mut rng, prikey, ct, session_key_len: msg.len)!

	assert key.len > 0
	assert '12345678abcde' == key.bytestr()
}

fn test_encrypt_privatekey_pkcs1v15() {
	prikey := get_prikey3()!
	pubkey := prikey.public()

	msg := '12345678abcde'.bytes()

	{
		ciphertext := encrypt_privatekey_pkcs1v15(prikey, msg)!
		assert ciphertext.len > 0

		demsg := decrypt_publickey_pkcs1v15(pubkey, ciphertext)!
		assert demsg.len > 0
		assert '12345678abcde' == demsg.bytestr()
	}
	{
		ciphertext := '7b1783ab067d84749b14f4da0fe63467a16c087ac1edf552387665e73047ebd1cc881fc064b5b2e427ceebefd50616f9ada687c828416e44bdaf29ed07d62551'
		ct := from_hex(ciphertext)!

		demsg := decrypt_publickey_pkcs1v15(pubkey, ct)!
		assert demsg.len > 0
		assert 'rsa PKCS1-v1_5 encrypt and decrypt' == demsg.bytestr()
	}
}

fn test_encrypt_privatekey_pkcs1v15_key() {
	prikey := get_prikey31()!
	pubkey := prikey.public()

	msg := '12345678abcde'.bytes()

	{
		ciphertext := encrypt_privatekey_pkcs1v15(prikey, msg)!
		assert ciphertext.len > 0

		demsg := decrypt_publickey_pkcs1v15(pubkey, ciphertext)!
		assert demsg.len > 0
		assert '12345678abcde' == demsg.bytestr()
	}

}

fn test_encrypt_pkcs1v15_2() {
	prikey := get_prikey3()!
	pubkey := prikey.public()

	mut rng := get_rng()

	msg := '12345678abcde'.bytes()

	{
		ciphertext := encrypt_pkcs1v15(mut rng, pubkey, msg)!
		assert ciphertext.len > 0

		demsg := decrypt_pkcs1v15(prikey, ciphertext)!
		assert demsg.len > 0
		assert '12345678abcde' == demsg.bytestr()
	}
	{
		ciphertext := '24d17d224f3181383660c4e7d3d4092cc9f7fb015b344aa24afb90e1979fdfc35e7561b1fe217eb18371bf84a8b54e27b043d7b2f69d0418d6621ff0ab10c484'
		ct := from_hex(ciphertext)!

		demsg := decrypt_pkcs1v15(prikey, ct)!
		assert demsg.len > 0
		assert 'rsa PKCS1-v1_5 encrypt and decrypt' == demsg.bytestr()
	}

}
