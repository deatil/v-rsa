module rsa

import rand.seed
import rand.mt19937
import math.big
import encoding.hex
import crypto.sha256

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
    n := big.integer_from_radix("9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767", 16)!
    e := big.integer_from_radix("010001", 16)!
    d := big.integer_from_radix("63d392db30747f975f948ddd0e4205a43d743e8b775a1a670a55673b087ca0f0a7c1edc9ed97d5ffd852a02c53109a95ac4feff9f4ce38c7f7109939e99ac98b746ebde3faa182d07e73e754955da8cfb1f44f6e66363bbb0436c0b331e58d9d6a1c45ee3543f75e57d3aba8a89edf6a602235a01fa3afbce49b9632159faa70b570ac22d54af63e1c2f09869d91a0a4cbe4f2f4f0ba6c7469df09a1a121b7044df20b0e90089ae1e4d194bd72c85ead2db6de51b69961b0454b2ed3ac0ed9c1cd75dac818a6cb2d47ec0d950907ad14d68812b4ec83766795369c81fa10eab57c9774bf83f2d9eebc5f96c58d0a864bf005b905cf26deda7c5220754e2ee2b9", 16)!
    p := big.integer_from_radix("cc558bc7e22c34a9b5012f75ed39ccb284f2f4a64af78652b5cb6f77999202344161192ae63a5cd048d1943b80b98a66e15142187efc2d471f0f7d258843790d87b190a2a522a299b3b8ccf1d250b3003394d29ff6a9a79bbf9b08219d45969147dad74b44ad223adbebf48a2a0dd9ad394a8838fc8bbadc7025001663e4b46b", 16)!
    q := big.integer_from_radix("c4c5b893ac7215a18383cba6b27bb4e0f8a7890649da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5", 16)!
    
    mut prikey := PrivateKey{
        PublicKey: PublicKey{
            n: n
            e: e.int()
        }
        d: d
        primes: [p, q]
    }

    prikey.precompute()!

	return prikey
}

pub fn test_sign_pss() {
	prikey := get_prikey()!
	pubkey := prikey.public()

	mut rng := get_rng()

	msg := "12345678abcde".bytes()

	mut d := sha256.new()
	d.reset()
	d.write(msg)!
	hashed := d.sum([])

	signed := sign_pss(mut rng, prikey, mut d, hashed)!
	assert signed.len > 0

	// assert "123" == signed.hex()

	verify_pss(pubkey, mut d, hashed, signed)!
}

pub fn test_sign_pss2() {
	prikey := get_prikey()!
	pubkey := prikey.public()

	mut rng := get_rng()

	msg := "12345678abcde".bytes()

	mut d := sha256.new()
	d.reset()
	d.write(msg)!
	hashed := d.sum([])

	opts := PSSOptions{
		salt_leng: pss_salt_length_equals_hash
	}

	signed := sign_pss(mut rng, prikey, mut d, hashed, opts)!
	assert signed.len > 0

	verify_pss(pubkey, mut d, hashed, signed, opts)!
}

pub fn test_sign_pss3() {
	prikey := get_prikey()!
	pubkey := prikey.public()

	mut rng := get_rng()

	msg := "12345678abcde".bytes()

	mut d := sha256.new()
	d.reset()
	d.write(msg)!
	hashed := d.sum([])

	opts := PSSOptions{
		salt_leng: pss_salt_length_equals_hash
		hash: sha256.new()
	}

	signed := sign_pss(mut rng, prikey, mut d, hashed, opts)!
	assert signed.len > 0

	verify_pss(pubkey, mut d, hashed, signed, opts)!
}

pub fn test_verify_pss_check() {
	prikey := get_prikey()!
	pubkey := prikey.public()

	msg := "12345678abcde".bytes()

	mut d := sha256.new()
	d.reset()
	d.write(msg)!
	hashed := d.sum([])
	
	ciphertext := "794ed1f1eb627dcc8115590771f40047d9a64858182c583abe8431329f53380a128711d93eb087c4fbf349015b34fa5c19aab0a0014b6b357d30ede2b3948047f5b448c7180c7fd4407e1aef4b8edd419369c2d63448c4c7acbee018a697bd398e202f916cc249b935f738cc3d744c1609a6aaf4ee2448cce647e37d5175ec298eb28ae415b0c5fd1f22fe866256f6b14a762de0b34b702e9a6aed04672ce355d4598622e6c89c1bd3beae7ef71e83c7814048f100d6c377c4b97086b9a9ca6b25c59c40240b1b1696760022868ee34f3f75a7a95d5abcdd4e6ae58e7912f46545186838320d4f96d7ed03e9a88939b57ec6ced1649b9293c65eaa84bdf9ded9"
	signed := from_hex(ciphertext)!

	verify_pss(pubkey, mut d, hashed, signed)!
}

pub fn test_verify_pss_check_fail() {
	prikey := get_prikey()!
	pubkey := prikey.public()

	msg := "12345678abcde".bytes()

	mut d := sha256.new()
	d.reset()
	d.write(msg)!
	hashed := d.sum([])
	
	ciphertext := "794ed1f1eb627dcc8115590771f40047d9a64858182c583abe8431329f53380a128711d93eb087c4fbf349015b34fa5c19aab0a0014b6b357d30ede2b3948047f5b448c7180c7fd4407e1aef4b8edd419369c2d63448c4c7acbee018a697bd398e202f916cc249b935f738cc3d744c1609a6aaf4ee2448cce647e37d5175ec298eb28ae415b0c5fd1f22fe866256f6b14a762de0b34b702e9a6aed04672ce355d4598622e6c89c1bd3beae7ef71e83c7814048f100d6c377c4b97086b9a9ca6b25c59c40240b1b1696760022868ee34f3f75a7a95d5abcdd4e6ae58e7912f46545186838320d4f96d7ed03e9a88939b57ec6ced1649b9293c65eaa84bdf9ded8"
	signed := from_hex(ciphertext)!

	mut need_err := false
	verify_pss(pubkey, mut d, hashed, signed) or {
		assert err.msg() == "v-rsa: verification error"
		need_err = true
	}
	assert true == need_err
}
