module rsa

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

pub fn test_encrypt_pkcs1v15() {
	prikey := get_prikey()!
	pubkey := prikey.public()

	mut rng := get_rng()

	msg := "12345678abcde".bytes()

	ciphertext := encrypt_pkcs1v15(mut rng, pubkey, msg)!
	assert ciphertext.len > 0

	demsg := decrypt_pkcs1v15(prikey, ciphertext)!
	assert demsg.len > 0
	assert "12345678abcde" == demsg.bytestr()
}

pub fn test_decrypt_pkcs1v15_check() {
	prikey := get_prikey()!

	msg := "12345678abcde".bytes()
	ciphertext := "24cb659f249d437efb94652b840e09c7124a1d9db2737d38979ac534cb038fd01c35fb1619fec7eaa2424c0c90f2827dc45ea925f9cd79607e4270895ef9f8142055ad2009fe273626c481df5835c96e0c4838b7bda3e45336b381434cbec1acd5f4480d61a08c2c304e773c03b8171c2c6f0aae8e07a8f600c688e6126ca69a99a9166cfa67ec61791b84f1966892ab3ff6f853d7482a83c7b25a35a4837f370d3f9fa6b523cd3734299ab5b400d2b2d15b20747f4384acd4749334e14835f691e5f4e3ca41cfdf269f486818f53f7a874ad7b366fdb23dbc840a8ebc504a1488280dfb1041ff461825b6da794d60efc8844312030c590cf414fa1c93008115"
	ct := from_hex(ciphertext)!

	demsg := decrypt_pkcs1v15(prikey, ct)!
	assert demsg.len > 0
	assert "12345678abcde" == demsg.bytestr()
}

pub fn test_decrypt_pkcs1v15_session_key_check() {
	prikey := get_prikey()!

	msg := "12345678abcde".bytes()
	ciphertext := "24cb659f249d437efb94652b840e09c7124a1d9db2737d38979ac534cb038fd01c35fb1619fec7eaa2424c0c90f2827dc45ea925f9cd79607e4270895ef9f8142055ad2009fe273626c481df5835c96e0c4838b7bda3e45336b381434cbec1acd5f4480d61a08c2c304e773c03b8171c2c6f0aae8e07a8f600c688e6126ca69a99a9166cfa67ec61791b84f1966892ab3ff6f853d7482a83c7b25a35a4837f370d3f9fa6b523cd3734299ab5b400d2b2d15b20747f4384acd4749334e14835f691e5f4e3ca41cfdf269f486818f53f7a874ad7b366fdb23dbc840a8ebc504a1488280dfb1041ff461825b6da794d60efc8844312030c590cf414fa1c93008115"
	ct := from_hex(ciphertext)!

	mut key := []u8{len: msg.len}
	decrypt_pkcs1v15_session_key(prikey, ct, mut key)!

	assert key.len > 0
	assert "12345678abcde" == key.bytestr()
}

pub fn test_decrypt_pkcs1v15_session_key_with_opts_check() {
	prikey := get_prikey()!

	msg := "12345678abcde".bytes()
	ciphertext := "24cb659f249d437efb94652b840e09c7124a1d9db2737d38979ac534cb038fd01c35fb1619fec7eaa2424c0c90f2827dc45ea925f9cd79607e4270895ef9f8142055ad2009fe273626c481df5835c96e0c4838b7bda3e45336b381434cbec1acd5f4480d61a08c2c304e773c03b8171c2c6f0aae8e07a8f600c688e6126ca69a99a9166cfa67ec61791b84f1966892ab3ff6f853d7482a83c7b25a35a4837f370d3f9fa6b523cd3734299ab5b400d2b2d15b20747f4384acd4749334e14835f691e5f4e3ca41cfdf269f486818f53f7a874ad7b366fdb23dbc840a8ebc504a1488280dfb1041ff461825b6da794d60efc8844312030c590cf414fa1c93008115"
	ct := from_hex(ciphertext)!

	mut rng := get_rng()

	key := decrypt_pkcs1v15_session_key_with_opts(mut rng, prikey, ct, session_key_len: msg.len)!

	assert key.len > 0
	assert "12345678abcde" == key.bytestr()
}
