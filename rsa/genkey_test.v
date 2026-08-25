module rsa

import rand.seed
import rand.mt19937

pub fn test_generate_key() {
	seed_data := seed.time_seed_array(2)

	mut rnd := &mt19937.MT19937RNG{}
	rnd.seed(seed_data)

	prikey := generate_key(mut rnd, 1024)!
	assert 128 == prikey.size()

	prikey2 := generate_key(mut rnd, 1024)!
	assert 128 == prikey2.size()
	assert false == prikey.equal(prikey2)

	pubkey := prikey.public()
	pubkey2 := prikey2.public()
	assert false == pubkey.equal(pubkey2)
}

pub fn test_generate_key2() {
	/*
	seed_data := seed.time_seed_array(2)
	
	mut rnd := &mt19937.MT19937RNG{}
	rnd.seed(seed_data)

	{
		prikey := generate_key(mut rnd, 512)!
		assert 64 == prikey.size()
	}

	{
		prikey := generate_key(mut rnd, 2048)!
		assert 256 == prikey.size()
	}

	{
		prikey := generate_key(mut rnd, 4096)!
		assert 512 == prikey.size()
	}
	*/
}
