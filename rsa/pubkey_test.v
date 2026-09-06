module rsa

import math.big
import crypto.pem
import rand.seed
import rand.mt19937
import crypto.sha256
import crypto.sha512
import encoding.base64

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

fn test_make_prikey_pkcs1_der() {
	prikey := get_prikey()!
	pubkey := prikey.public()

	{
		der := make_prikey_pkcs1_der(prikey)!
		assert der.len > 0

		prikey2 := parse_prikey_pkcs1_der(der)!
		assert true == prikey.equal(prikey2)
	}

	{
		der := make_pubkey_pkcs1_der(pubkey)!
		assert der.len > 0

		pubkey2 := parse_pubkey_pkcs1_der(der)!
		assert true == pubkey.equal(pubkey2)
	}
}

fn test_make_prikey_pkcs8_der() {
	prikey := get_prikey()!
	pubkey := prikey.public()

	{
		der := make_prikey_pkcs8_der(prikey)!
		assert der.len > 0

		prikey2 := parse_prikey_pkcs8_der(der)!
		assert true == prikey.equal(prikey2)
	}

	{
		der := make_pubkey_pkcs8_der(pubkey)!
		assert der.len > 0

		pubkey2 := parse_pubkey_pkcs8_der(der)!
		assert true == pubkey.equal(pubkey2)
	}
}

fn test_private_key_precompute_from_key_der() {
	key_der := "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDh/nCDmXaEqxN416b9XjV8acmbqA52uPzKbesWQRT/BPxEO2dKAURk5CkcSBDskvfzFR9TRjeDppjD1BPSEnuYKnP0SvmotoxcnBnHMfMBqGV8DSJyppu8k4y9C3MPq5C/rA8TJm0NNaJCL0BfAGkeyw+elgYifbRlm42VfYGsKVyIeEI9Qghk5Cf8yapMPfWNLKOhChXsyGExMBMonHZeseFH7UNwonNAFJMAaelhVqqmwBFqn6fBGKmvedRO7HIaiEFNKaMna6xJ5Bccjds4MhF7UC5PIdx4Bt7CfxvjrbIRYoBF2l30CNBblIhU992zPkHoaVhDkt1gq3OdO7LvAgMBAAECggEBALCJrWTv7ahnZ3efpqAIBuogTVBd8KaHjVmokds5jehFAbdfXClwYfgaT477MNVNXYmzN1w63sTl0DIxqiYRMCFHEHuGUg6cQ3tYqb50Y2spG9XTANTlF4UxEeDfX8ue7xz7kG8aNlf6TL084iEUVgmrAJGWikZJQjGZWPmtKC3OTeJY5Bev5qHVuMRe+XEM5aQc3ph+lXlOF0Qp0Eg8YRWprrev2faH6prMqu2JGomoac6sfM4QJhtEViF7Gw0XPthPTbF19IefuAwi9psMM/9CnQ+MTWN2i6IxoUdicsFuC+Wdlb3K5V/+uldNSr+ePEhcya+YTLK9IOcVwWKQHykCgYEA8XvuEribf+t0ZPtfxr+DC9nZHXbVoFx0/ARpSG+P/fp3Hn3rO9iYQ6OtZ9mEXTzf+dhYTaRWq6PbCOz6i0It+J8QSBdxU9OcQ4871mDe41IvSc1CCGMW4PeIYtNQEK0zrqhN7SMtKyUd7yAsYRCrIzMc7NjE2qJvFw5kh7xC3Q0CgYEA75Qjn5daNYSAOa/ILdOs5J/8oIaO27RNK/fSKm/btsMsyum8+YP/mWmm1MXBzG9WEKzZv5yEKOWCEVJYVsFQsGt9yLYW2WIKU5UxiuU0F1RImF/dphIbYOh7oGC3WfYKk2f+K7ftjc196ZkEkDuE2Xh1h75/67Mzztx1DbXj6OsCgYBcDRfFfyWXb5Og4smxo1M680H2H1RzmorlfnD7sbs733wE3Y8L8xanwf7Z9WqleA0Q2k1e22RGbWGTV3JyHzoS6d90+6qxf5qzjigLIkYUdUGdambfd5ZDD1ioA1Ej6kInM/TwjlYreiyc+LCyF36FHnjKOB9iEEU0jsH3k+YRCQKBgHMVLPuHX6zfhhyvxK/Gw4FbHKYbnNoKxRs+wvThoKAtJwIdv0n4TzppVttUV2CVhrkh3sM9MvrWLGGXtZmO6Oyl5dkZJuarQpydyRuYOCqQsQKI4lbY0c/+PQxwCQMsvi3KwXxMsM7yC+6/M0L5ZDp2s7ZOGvKktVlD6vJ4Eg+bAoGARnGGprSBW8dAb/s53r0paPh4k/bySrXdGEprLwk6g3S8+aylcmjUdjcIq4dEb4A/nv12dx1Sc4y99c62R0zi+TT6FYBIFDMz3HNVzO0Jr6SgC6CNVotL0D725CioR5U1NyTHHRLZth69HLuEZCZQlPJCbePXMRRHmOl1svzcVuo="
	key_str := base64.url_decode_str(key_der)
    
    mut prikey := parse_prikey_pkcs8_der(key_str.bytes())!
    prikey.precompute()!

	assert 256 == prikey.size()

    dp := "5c0d17c57f25976f93a0e2c9b1a3533af341f61f54739a8ae57e70fbb1bb3bdf7c04dd8f0bf316a7c1fed9f56aa5780d10da4d5edb64466d61935772721f3a12e9df74fbaab17f9ab38e280b22461475419d6a66df7796430f58a8035123ea422733f4f08e562b7a2c9cf8b0b2177e851e78ca381f621045348ec1f793e61109"
    dq := "73152cfb875facdf861cafc4afc6c3815b1ca61b9cda0ac51b3ec2f4e1a0a02d27021dbf49f84f3a6956db5457609586b921dec33d32fad62c6197b5998ee8eca5e5d91926e6ab429c9dc91b98382a90b10288e256d8d1cffe3d0c7009032cbe2dcac17c4cb0cef20beebf3342f9643a76b3b64e1af2a4b55943eaf278120f9b"
    q_inv := "467186a6b4815bc7406ffb39debd2968f87893f6f24ab5dd184a6b2f093a8374bcf9aca57268d4763708ab87446f803f9efd76771d52738cbdf5ceb6474ce2f934fa158048143333dc7355cced09afa4a00ba08d568b4bd03ef6e428a84795353724c71d12d9b61ebd1cbb8464265094f2426de3d731144798e975b2fcdc56ea"

	assert dp == prikey.precomputed.dp.hex()
	assert dq == prikey.precomputed.dq.hex()
	assert q_inv == prikey.precomputed.q_inv.hex()

	assert 0 == prikey.precomputed.crt_values.len
}

fn test_sign_pss_with_pkcs1_key() {
	prikey_pem := "-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdr
j8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aY
w9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQ
tzD6uQv6wPEyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2B
rClciHhCPUIIZOQn/MmqTD31jSyjoQoV7MhhMTATKJx2Xr
HhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohB
TSmjJ2usSeQXHI3bODIRe1AuTyHceAbewn8b462yEWKARd
pd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQABAoIB
AQCwia1k7+2oZ2d3n6agCAbqIE1QXfCmh41ZqJHbOY3oRQ
G3X1wpcGH4Gk+O+zDVTV2JszdcOt7E5dAyMaomETAhRxB7
hlIOnEN7WKm+dGNrKRvV0wDU5ReFMRHg31/Lnu8c+5BvGj
ZX+ky9POIhFFYJqwCRlopGSUIxmVj5rSgtzk3iWOQXr+ah
1bjEXvlxDOWkHN6YfpV5ThdEKdBIPGEVqa63r9n2h+qazK
rtiRqJqGnOrHzOECYbRFYhexsNFz7YT02xdfSHn7gMIvab
DDP/Qp0PjE1jdouiMaFHYnLBbgvlnZW9yuVf/rpXTUq/nj
xIXMmvmEyyvSDnFcFikB8pAoGBAPF77hK4m3/rdGT7X8a/
gwvZ2R121aBcdPwEaUhvj/36dx596zvYmEOjrWfZhF083/
nYWE2kVquj2wjs+otCLfifEEgXcVPTnEOPO9Zg3uNSL0nNQ
ghjFuD3iGLTUBCtM66oTe0jLSslHe8gLGEQqyMzHOzYxNq
ibxcOZIe8Qt0NAoGBAO+UI5+XWjWEgDmvyC3TrOSf/KCGjt
u0TSv30ipv27bDLMrpvPmD/5lpptTFwcxvVhCs2b+chCjlg
hFSWFbBULBrfci2FtliClOVMYrlNBdUSJhf3aYSG2Doe6Bg
t1n2CpNn/iu37Y3NfemZBJA7hNl4dYe+f+uzM87cdQ214+j
rAoGAXA0XxX8ll2+ToOLJsaNTOvNB9h9Uc5qK5X5w+7G7O9
98BN2PC/MWp8H+2fVqpXgNENpNXttkRm1hk1dych86Eunfd
PuqsX+as44oCyJGFHVBnWpm33eWQw9YqANRI+pCJzP08I5W
K3osnPiwshd+hR54yjgfYhBFNI7B95PmEQkCgYBzFSz7h1+
s34Ycr8SvxsOBWxymG5zaCsUbPsL04aCgLScCHb9J+E86aV
bbVFdglYa5Id7DPTL61ixhl7WZjujspeXZGSbmq0Kcnckbm
DgqkLECiOJW2NHP/j0McAkDLL4tysF8TLDO8gvuvzNC+WQ6
drO2ThrypLVZQ+ryeBIPmwKBgEZxhqa0gVvHQG/7Od69KWj
4eJP28kq13RhKay8JOoN0vPmspXJo1HY3CKuHRG+AP579dn
cdUnOMvfXOtkdM4vk0+hWASBQzM9xzVcztCa+koAugjVaLS
9A+9uQoqEeVNTckxx0S2bYevRy7hGQmUJTyQm3j1zEUR5jp
dbL83Fbq
-----END RSA PRIVATE KEY-----"
	pubkey_pem := "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rF
kEU/wT8RDtnSgFEZOQpHEgQ7JL38xUfU0Y3g6aYw9QT0hJ7mC
pz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wPEyZ
tDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn
/MmqTD31jSyjoQoV7MhhMTATKJx2XrHhR+1DcKJzQBSTAGnpY
VaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3bODIRe1
AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5L
dYKtznTuy7wIDAQAB
-----END RSA PUBLIC KEY-----"

	block1, _ := pem.decode(prikey_pem) or {pem.Block{}, ""}
	prikey := parse_prikey_pkcs1_der(block1.data)!

	block2, _ := pem.decode(pubkey_pem) or {pem.Block{}, ""}
	pubkey := parse_pubkey_pkcs1_der(block2.data)!

	mut rng := get_rng()

	msg := "12345678abcde".bytes()

	mut d := sha256.new()
	d.reset()
	d.write(msg)!
	hashed := d.sum([])

	signed := sign_pss(mut rng, prikey, mut d, hashed)!
	assert signed.len > 0

	verify_pss(pubkey, mut d, hashed, signed)!
}

fn test_sign_pss_with_pkcs8_key() {
	prikey_pem := "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD2Krfw7XGOKS7g
PHi7jX3d8xXGbOoz1CXgRDtm22nQatzGqTbyPuC02Ae/O2zKgZP41tBT6OLWsuCv
RU0pE+AC0MAFvyD0jg2qpOyP4Ye5hBF7DFk0oQeVqMEj4p4T06JheYMw3mD1Tro9
k51MXCy/fsQ0wnzVYJh24cjMrM5Li0XNKGRO0aLjAQConjZNebX/Q9/XqP4wjJyL
/btwSLusdedv/3GYX0oTBkDbiDe4Ju3m4rXSN2aRyJ2gs8c/5xn1rK83rm1rwH+O
6LDOSfq66TxhEXv3x2w+c2qWgiB78ybo35GbMZKOWp+pBCDh1Cfp5TvToDOj8J1E
81ed/xRNAgMBAAECggEBAOr/9QGHa3RvVFS05f0GIjaULSF0MFCyIkZqXNrgc6+H
lKQCPnYcGKAL67lfnYflE8HmMJMqLAMSWPR5kCO62YtWhTn3MBrG0b0qHLtubgdo
UNfK/g4D/B2fMGJ1oLsEumubeOZaJO2J7rmCBhQzmnRlLCHB2TJKOMKk4PCjt3zc
5K33aFNf3N+NvnbsD38WeKXnOx6bIRJhPSqkS+Ck0NmHr0d7Ga9qoiH3/AAIcjoE
Lzs3Don6+v7tAOqH9tfhhWY9E05O8dJH+vDlktRq9ctCXQaOK2UqLsYENPIPgtFj
cys5/2U5OsmmgltPPCyZkdCEkdY+BTMnlNncpUznFwECgYEA/+Z0f7N4C77RH247
4nAR3eRRu9HsuRQeHsbg0X/ARHvJCZ6dwPGj7n2XkTVg/cI7IJUxcoKMBKzvfAP3
rVQ9JVpSliyuJcJ4IW/xxBDVMR/9T4uD4ht4BzjppCW5ffPSGGTPViUrmcorbVj/
UhrV/BC2G/IXFkBedpw72JIGnX0CgYEA9kNKtS33iILtID0871c8Pi+q0xABPipJ
Ax1G+9M7nYM6vAGwHflil4Shg8S1g5IFn9p2zu+WaXbT3JfvgVAkEPS0+pHXcXEa
WraF6Pvbbw1xSMPla23wezLMOvt+hTsQGRQCLa7ZCyruvghCHxvAbJawyuQKViEd
4Mw6QfEHSxECgYBHDKFD43xtJmnBpEWUNTGAvifDUiG7sU47lVROVn33hbbnqNZ7
/5tYWB6A/qUTT55DCalU9dISakGD2UYnJcBkYpOThoxDh577Ca3CljnbDdqy/zV6
zc2hk7erD55UziGDDFpUvLVCWdN85Lze+vx2o90sHScz0mNn4zDqjICxsQKBgF/4
MXESDNlCTK63rruHP47sfKHsJs/XIsT37+XLl/v2XDlQXxYPTgDGSztSuXogudhm
Bs72R6OqDz50Z335gVSqSK0tkMxAy4h2gREetZE9p9w3m3yWR5V7YmPKBrBdKBTd
20t6TFMx1AByr3H4GrE2uIcY/345Qa+NZ1azW6hBAoGAT+7KzpWJw/jUWbgtEHlA
nJR05Iu4RPzXZh2D9xZHWZ6hIQMd8Eg/wI5/5xfoWbq3exhRODY4zVlmVwSSiiNG
7vS6P/BIYEM4q4Uv9+dPccUaVBP6Nf+u8CZUMPzvWMkXTHIhPKOoVhfRg8luzulJ
ccx6QUrMWw06MLxvvr+7bcs=
-----END PRIVATE KEY-----"
	pubkey_pem := "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9iq38O1xjiku4Dx4u419
3fMVxmzqM9Ql4EQ7Zttp0Grcxqk28j7gtNgHvztsyoGT+NbQU+ji1rLgr0VNKRPg
AtDABb8g9I4NqqTsj+GHuYQRewxZNKEHlajBI+KeE9OiYXmDMN5g9U66PZOdTFws
v37ENMJ81WCYduHIzKzOS4tFzShkTtGi4wEAqJ42TXm1/0Pf16j+MIyci/27cEi7
rHXnb/9xmF9KEwZA24g3uCbt5uK10jdmkcidoLPHP+cZ9ayvN65ta8B/juiwzkn6
uuk8YRF798dsPnNqloIge/Mm6N+RmzGSjlqfqQQg4dQn6eU706Azo/CdRPNXnf8U
TQIDAQAB
-----END PUBLIC KEY-----"

	block1, _ := pem.decode(prikey_pem) or {pem.Block{}, ""}
	prikey := parse_prikey_pkcs8_der(block1.data)!

	block2, _ := pem.decode(pubkey_pem) or {pem.Block{}, ""}
	pubkey := parse_pubkey_pkcs8_der(block2.data)!

	mut rng := get_rng()

	msg := "12345678abcde".bytes()

	mut d := sha256.new()
	d.reset()
	d.write(msg)!
	hashed := d.sum([])

	signed := sign_pss(mut rng, prikey, mut d, hashed)!
	assert signed.len > 0

	verify_pss(pubkey, mut d, hashed, signed)!
}

fn test_sign_pss_with_pkcs1_key_check() {
	pubkey_pem := "-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8ym3rFkEU/wT8RDtnSgFEZOQpHEgQ
7JL38xUfU0Y3g6aYw9QT0hJ7mCpz9Er5qLaMXJwZxzHzAahlfA0icqabvJOMvQtzD6uQv6wP
EyZtDTWiQi9AXwBpHssPnpYGIn20ZZuNlX2BrClciHhCPUIIZOQn/MmqTD31jSyjoQoV7Mhh
MTATKJx2XrHhR+1DcKJzQBSTAGnpYVaqpsARap+nwRipr3nUTuxyGohBTSmjJ2usSeQXHI3b
ODIRe1AuTyHceAbewn8b462yEWKARdpd9AjQW5SIVPfdsz5B6GlYQ5LdYKtznTuy7wIDAQAB
-----END RSA PUBLIC KEY-----"

	block2, _ := pem.decode(pubkey_pem) or {pem.Block{}, ""}
	pubkey := parse_pubkey_pkcs1_der(block2.data)!

	msg := "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIifQ".bytes()

	mut d := sha512.new384()
	d.reset()
	d.write(msg)!
	hashed := d.sum([])

	sig := "w7-qqgj97gK4fJsq_DCqdYQiylJjzWONvD0qWWWhqEOFk2P1eDULPnqHRnjgTXoO4HAw4YIWCsZPet7nR3Xxq4ZhMqvKW8b7KlfRTb9cH8zqFvzMmybQ4jv2hKc3bXYqVow3AoR7hN_CWXI3Dv6Kd2X5xhtxRHI6IL39oTVDUQ74LACe-9t4c3QRPuj6Pq1H4FAT2E2kW_0KOc6EQhCLWEhm2Z2__OZskDC8AiPpP8Kv4k2vB7l0IKQu8Pr4RcNBlqJdq8dA5D3hk5TLxP8V5nG1Ib80MOMMqoS3FQvSLyolFX-R_jZ3-zfq6Ebsqr0yEb0AH2CfsECF7935Pa0FKQ"
	signed := base64.url_decode_str(sig)

	verify_pss(pubkey, mut d, hashed, signed.bytes())!
}

fn test_parse_pkcs8_der_key_fail() {
	prikey_pem := "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIK3jWwBPmk1J4dynA3CjSfOLP9seazHZYZ6MCqCU+n0f
-----END PRIVATE KEY-----"
	pubkey_pem := "-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAj/CWF9RnNKe/L0jHWHpUICXDowaNYLbj7Ck/wdzTvE4=
-----END PUBLIC KEY-----"

	block1, _ := pem.decode(prikey_pem) or {pem.Block{}, ""}

	mut need_err := false
	parse_prikey_pkcs8_der(block1.data) or {
		need_err = true
		assert "v-rsa: rsa oid error" == err.msg()
	}
	assert true == need_err

	block2, _ := pem.decode(pubkey_pem) or {pem.Block{}, ""}

	mut need_err2 := false
	parse_pubkey_pkcs8_der(block2.data) or {
		need_err2 = true
		assert "v-rsa: rsa oid error" == err.msg()
	}
	assert true == need_err
}

fn test_parse_pkcs1_pem_key_with_crts() {
	prikey_pem := "-----BEGIN RSA PRIVATE KEY-----
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
7SEsFcPwusoU1g==
-----END RSA PRIVATE KEY-----"

	block1, _ := pem.decode(prikey_pem) or {pem.Block{}, ""}

	prikey := parse_prikey_pkcs1_der(block1.data)!
	assert 512 == prikey.size()

}

fn test_parse_pkcs8_pem_key_with_crts() {
	prikey_pem := "-----BEGIN PRIVATE KEY-----
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
-----END PRIVATE KEY-----"

	block1, _ := pem.decode(prikey_pem) or {pem.Block{}, ""}

	prikey := parse_prikey_pkcs8_der(block1.data)!
	assert 512 == prikey.size()

}

