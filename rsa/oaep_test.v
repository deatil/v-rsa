module rsa

import crypto.sha1
import crypto.sha256
import rand.seed
import rand.mt19937
import math.big
import encoding.hex

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

pub fn test_encrypt_oaep() {
	prikey := get_prikey()!
	pubkey := prikey.public()

	mut h := sha1.new()
	mut rng := get_rng()

	msg := '12345678abcde'.bytes()
	label := 'label-test'.bytes()

	ciphertext := encrypt_oaep(mut h, mut rng, pubkey, msg, label)!
	assert ciphertext.len > 0

	demsg := decrypt_oaep(mut h, prikey, ciphertext, label)!
	assert demsg.len > 0
	assert '12345678abcde' == demsg.bytestr()
}

pub fn test_decrypt_oaep_check() {
	prikey := get_prikey()!

	mut h := sha1.new()

	msg := '12345678abcde'.bytes()
	ciphertext := '877611149e10ea45cb80b5497a8466c99cbff0ecdaf8b56d9566e3d96335d5f5913f2b627c9857eb39b96ce2e0811ef22e617f8010fcd4a7e84efaad6c6be1a14cda0fb75287a2b8439236e9cf2addf4ef0d4e2813e506adf767badbed42c3bdeb5d493f5b6954018cce4923d6a2e1701bb45eb9b247cecfe37a8a3c5694abd990b5b7ad6d4e0b6d35dbb2565ab10303fb430848ab153be882faa0f972e8a0dbb1aa2061d87769210f528b89bd0d22823982255241d86fed085b7b5d6e1b01ee2ee699058710086d55f079071f0cad5f61caf3be4ff0de8036964b7f3642c05af996fbd673c6e79c90158a0ab7f517f83988f3062d54790a2446927bd6269034'
	ct := from_hex(ciphertext)!
	label := 'label-test'.bytes()

	demsg := decrypt_oaep(mut h, prikey, ct, label)!
	assert demsg.len > 0
	assert '12345678abcde' == demsg.bytestr()
}

pub fn test_encrypt_oaep_with_opts() {
	prikey := get_prikey()!
	pubkey := prikey.public()

	mut rng := get_rng()

	msg := '12345678abcde'.bytes()
	label := 'label-test'.bytes()

	opts := OAEPOptions{
		hash:     sha1.new()
		mgf_hash: sha1.new()
		label:    label
	}

	ciphertext := encrypt_oaep_with_opts(mut rng, pubkey, msg, opts)!
	assert ciphertext.len > 0

	demsg := decrypt_oaep_with_opts(prikey, ciphertext, opts)!
	assert demsg.len > 0
	assert '12345678abcde' == demsg.bytestr()
}

pub fn test_encrypt_oaep_with_opts2() {
	prikey := get_prikey()!
	pubkey := prikey.public()

	mut rng := get_rng()

	msg := '12345678abcde'.bytes()
	label := 'label-test'.bytes()

	opts := OAEPOptions{
		hash:     sha1.new()
		mgf_hash: sha256.new()
		label:    label
	}

	ciphertext := encrypt_oaep_with_opts(mut rng, pubkey, msg, opts)!
	assert ciphertext.len > 0

	// ciphertext = 75d2af1cf420c6e2b64c5b3e062457059eb2cea9afc01d19e3042105983cbfe1ad97cb782e0a489419d6cc9995c68f19595acdc21883f2815b9ae4bc1938a7a2788920358e67fa2b4974382517bdbe92f18cbf5588ee282cf40fe6a7669555bf6e4da6df96cfeb3ad50a42f501e7aebafdd070d54bbbdf4f1001127a9466114371c1b4f34bf15779bc71e3e017dc056a30a4bcde4c3a9e380e45af4a45e42b808181ef089c418daac4e4af0a65f9bff086e09d898540f5217c7d136979b682c8a394ea44b377c72abae714eb254c70604e6254c8c2f6f4c749805abd169cab062057e41d1df3d5709721b5837425af16db10d3bbe84d06fa3cb94b46360cb490

	demsg := decrypt_oaep_with_opts(prikey, ciphertext, opts)!
	assert demsg.len > 0
	assert '12345678abcde' == demsg.bytestr()
}

pub fn test_decrypt_oaep_with_opts_check() {
	prikey := get_prikey()!

	msg := '12345678abcde'.bytes()
	ciphertext := '877611149e10ea45cb80b5497a8466c99cbff0ecdaf8b56d9566e3d96335d5f5913f2b627c9857eb39b96ce2e0811ef22e617f8010fcd4a7e84efaad6c6be1a14cda0fb75287a2b8439236e9cf2addf4ef0d4e2813e506adf767badbed42c3bdeb5d493f5b6954018cce4923d6a2e1701bb45eb9b247cecfe37a8a3c5694abd990b5b7ad6d4e0b6d35dbb2565ab10303fb430848ab153be882faa0f972e8a0dbb1aa2061d87769210f528b89bd0d22823982255241d86fed085b7b5d6e1b01ee2ee699058710086d55f079071f0cad5f61caf3be4ff0de8036964b7f3642c05af996fbd673c6e79c90158a0ab7f517f83988f3062d54790a2446927bd6269034'
	ct := from_hex(ciphertext)!
	label := 'label-test'.bytes()

	opts := OAEPOptions{
		hash:     sha1.new()
		mgf_hash: sha1.new()
		label:    label
	}

	demsg := decrypt_oaep_with_opts(prikey, ct, opts)!
	assert demsg.len > 0
	assert '12345678abcde' == demsg.bytestr()
}

pub fn test_decrypt_oaep_with_opts_check2() {
	prikey := get_prikey()!

	msg := '12345678abcde'.bytes()
	ciphertext := '877611149e10ea45cb80b5497a8466c99cbff0ecdaf8b56d9566e3d96335d5f5913f2b627c9857eb39b96ce2e0811ef22e617f8010fcd4a7e84efaad6c6be1a14cda0fb75287a2b8439236e9cf2addf4ef0d4e2813e506adf767badbed42c3bdeb5d493f5b6954018cce4923d6a2e1701bb45eb9b247cecfe37a8a3c5694abd990b5b7ad6d4e0b6d35dbb2565ab10303fb430848ab153be882faa0f972e8a0dbb1aa2061d87769210f528b89bd0d22823982255241d86fed085b7b5d6e1b01ee2ee699058710086d55f079071f0cad5f61caf3be4ff0de8036964b7f3642c05af996fbd673c6e79c90158a0ab7f517f83988f3062d54790a2446927bd6269034'
	ct := from_hex(ciphertext)!
	label := 'label-test'.bytes()

	opts := OAEPOptions{
		hash:  sha1.new()
		label: label
	}

	demsg := decrypt_oaep_with_opts(prikey, ct, opts)!
	assert demsg.len > 0
	assert '12345678abcde' == demsg.bytestr()
}

pub fn test_decrypt_oaep_with_opts_check3() {
	prikey := get_prikey()!

	ciphertext := '599db7a8bd82e2762b06cded4398577544eb0502422eb64fe2c9c517d8a5b95b2ccff009ddc1b79ce4442224625c719cc33b2bae006b38cf2956a0889fe0be524364c4177b626faeb36ea9b2e45614a31add21ca644235d0f27a66984746c0f16f82f0f127cf37c2e93ecff0fd8d3b4ba1ad696d77a94ae26d479977921282fce7b654d3df80656a01d4d415e04bccff4acc0f5ab8197db3eea2f4a044e3e8736ddcfdac561eb4ef4559f6524e9e1531ec98a6b0535183e5013e0ebc56627c01d89df99fb1a5774f0a762dea30ed0b3f80c9ddae63db942606ac76dc930614edf8386afebc8ef348b4e106b2f8e27fb7357053f7d865193a48eceabc3c8e430e'
	ct := from_hex(ciphertext)!
	label := 'label-test'.bytes()

	opts := OAEPOptions{
		hash:     sha1.new()
		mgf_hash: sha256.new()
		label:    label
	}

	demsg := decrypt_oaep_with_opts(prikey, ct, opts)!
	assert demsg.len > 0
	assert 'message-data' == demsg.bytestr()
}
