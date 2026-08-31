## V-RSA 

A RSA library for vlang.


### Env

 - vlang >= 0.5.2


### Adding v-rsa as a dependency

Add the dependency to your project:

```bash
v install deatil.vrsa
```

or 

```bash
v install --git https://github.com/deatil/v-rsa
```

The `v-rsa` can be imported in your application with:

```v
import deatil.vrsa.rsa
```


### Get Starting

~~~v
module main

import rand
import deatil.vrsa.rsa

fn main() {
	mut rng := rand.new_default()

	prikey := rsa.generate_key(mut rng, 2048)!
	pubkey := prikey.public()

	msg := '12345678abcde'.bytes()
	hashed := rsa.hasher_sha256.hash_msg(msg)!

	signed := rsa.sign_pkcs1v15(mut rng, prikey, rsa.hasher_sha256, hashed)!

	println('sign_pkcs1v15: ${signed.hex()}')

	veri := if _ := rsa.verify_pkcs1v15(pubkey, rsa.hasher_sha256, hashed, signed) {
		true
	} else {
		false
	}

	println('verify_pkcs1v15: ${veri}')
}
~~~


### RSA functions

Generate key: 
~~~v
generate_key(mut random rand.PRNG, bits int) !PrivateKey
~~~

PKCS1v15 sign: 
~~~v
sign_pkcs1v15(mut random rand.PRNG, priv PrivateKey, hasher IHasher, hashed []u8) ![]u8
~~~

~~~v
verify_pkcs1v15(pubkey PublicKey, hasher IHasher, hashed []u8, sig []u8) !
~~~

PKCS1v15 encrypt: 
~~~v
encrypt_pkcs1v15(mut random rand.PRNG, pubkey PublicKey, msg []u8) ![]u8
~~~

~~~v
decrypt_pkcs1v15(priv PrivateKey, ciphertext []u8) ![]u8
~~~

OAEP encrypt: 
~~~v
encrypt_oaep(mut h hash.Hash, mut random rand.PRNG, pubkey PublicKey, msg []u8, label []u8) ![]u8
~~~

~~~v
decrypt_oaep(mut h hash.Hash, priv PrivateKey, ciphertext []u8, label []u8) ![]u8
~~~

PSS sign: 
~~~v
sign_pss(mut random rand.PRNG, priv PrivateKey, mut h hash.Hash, digest []u8, opts PSSOptions)
~~~

~~~v
verify_pss(pubkey PublicKey, mut h hash.Hash, digest []u8, sig []u8, opts PSSOptions) !
~~~


### PKCS1v15 Sign Hasher

 - `hasher_md5`: rsa.hasher_md5
 - `hasher_sha1`: rsa.hasher_sha1
 - `hasher_sha224`: rsa.hasher_sha224
 - `hasher_sha256`: rsa.hasher_sha256
 - `hasher_sha384`: rsa.hasher_sha384
 - `hasher_sha512`: rsa.hasher_sha512
 - `hasher_ripemd160`: rsa.hasher_ripemd160


### Parse PublicKey

PCKS1 prikey: 
~~~v
parse_prikey_pkcs1_der(bytes []u8) !PrivateKey
~~~

~~~v
make_prikey_pkcs1_der(prikey PrivateKey) ![]u8
~~~

PCKS1 pubkey: 
~~~v
parse_pubkey_pkcs1_der(bytes []u8) !PublicKey
~~~

~~~v
make_pubkey_pkcs1_der(pubkey PublicKey) ![]u8
~~~

PCKS8 prikey: 
~~~v
parse_prikey_pkcs8_der(bytes []u8) !PrivateKey
~~~

~~~v
make_prikey_pkcs8_der(prikey PrivateKey) ![]u8
~~~

PCKS8 pubkey: 
~~~v
parse_pubkey_pkcs8_der(bytes []u8) !PublicKey
~~~

~~~v
make_pubkey_pkcs8_der(pubkey PublicKey) ![]u8
~~~


### LICENSE

*  The library LICENSE is `Apache2`, using the library need keep the LICENSE.


### Copyright

*  Copyright deatil(https://github.com/deatil).
