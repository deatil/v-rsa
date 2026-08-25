module rsa

import math.big

fn test_public_key() {
    n := big.integer_from_radix("9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767", 16)!
    e := big.integer_from_radix("010001", 16)!
	pubkey := PublicKey{
        n: n
        e: e.int()
    }

    n2 := big.integer_from_radix("9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767", 16)!
    e2 := big.integer_from_radix("010001", 16)!
	pubkey2 := PublicKey{
        n: n2
        e: e2.int()
    }

	assert true == pubkey.equal(pubkey2)
	assert 256 == pubkey.size()

    n3 := big.integer_from_radix("d36c16b5be5229343add228db0f7e0ebe97d789c80ab66cb0bdadc12156fd5dad3447e11d9a2a6ac05337ccdd4143b36555e851ed20a81ce84e5780e91bfe4ee734467c2ed67fd961edf7e3e3a0dc591e19eab6fa662d25fa4655b48b7e635fef30be9a88e709a21248a152143c144c4d5e2a105705862cda613fc2719bd106595d43e4d1f520c5848f2ed96349bc93f49ff72658da96d24fb7c85d53a3771cd6009894f8478fd63c4d7a254c61e139a8c2b33c2b67f5e4798ec99dbb4204a65fa0ea904b5dd7c13819134997ebc85456bb89a27c766d8c2c588391eacef13bbd57221b1198b75a3bb0d28e01b7923de580429033c13c8f302843f56783f01dd", 16)!
    e3 := big.integer_from_radix("010001", 16)!
	pubkey3 := PublicKey{
        n: n3
        e: e3.int()
    }

	assert false == pubkey.equal(pubkey3)
}

fn test_check_pub() {
    {
        n := big.integer_from_radix("9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767", 16)!
        e := big.integer_from_radix("010001", 16)!
        pubkey := PublicKey{
            n: n
            e: e.int()
        }

        mut need_err := false
        check_pub(pubkey) or {
            need_err = true
        }

        assert false == need_err
    }

    {
        e := big.integer_from_radix("010001", 16)!
        pubkey := PublicKey{
            e: e.int()
        }

        mut need_err := false
        check_pub(pubkey) or {
            need_err = true
            assert "v-rsa: missing public modulus" == err.msg()
        }

        assert true == need_err
    }

    {
        n := big.integer_from_radix("9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767", 16)!
        pubkey := PublicKey{
            n: n
            e: 1
        }

        mut need_err := false
        check_pub(pubkey) or {
            need_err = true
            assert "v-rsa: public exponent too small" == err.msg()
        }

        assert true == need_err
    }

    {
        n := big.integer_from_radix("9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767", 16)!
        pubkey := PublicKey{
            n: n
            e: int(i64(1<<30)+1)
        }

        mut need_err := false
        check_pub(pubkey) or {
            need_err = true
            assert "v-rsa: public exponent too large" == err.msg()
        }

        assert false == need_err
    }
}

fn test_private_key() {
    n := big.integer_from_radix("9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767", 16)!
    e := big.integer_from_radix("010001", 16)!
    d := big.integer_from_radix("63d392db30747f975f948ddd0e4205a43d743e8b775a1a670a55673b087ca0f0a7c1edc9ed97d5ffd852a02c53109a95ac4feff9f4ce38c7f7109939e99ac98b746ebde3faa182d07e73e754955da8cfb1f44f6e66363bbb0436c0b331e58d9d6a1c45ee3543f75e57d3aba8a89edf6a602235a01fa3afbce49b9632159faa70b570ac22d54af63e1c2f09869d91a0a4cbe4f2f4f0ba6c7469df09a1a121b7044df20b0e90089ae1e4d194bd72c85ead2db6de51b69961b0454b2ed3ac0ed9c1cd75dac818a6cb2d47ec0d950907ad14d68812b4ec83766795369c81fa10eab57c9774bf83f2d9eebc5f96c58d0a864bf005b905cf26deda7c5220754e2ee2b9", 16)!
    p := big.integer_from_radix("cc558bc7e22c34a9b5012f75ed39ccb284f2f4a64af78652b5cb6f77999202344161192ae63a5cd048d1943b80b98a66e15142187efc2d471f0f7d258843790d87b190a2a522a299b3b8ccf1d250b3003394d29ff6a9a79bbf9b08219d45969147dad74b44ad223adbebf48a2a0dd9ad394a8838fc8bbadc7025001663e4b46b", 16)!
    q := big.integer_from_radix("c4c5b893ac7215a18383cba6b27bb4e0f8a7890649da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5", 16)!
    dp := big.integer_from_radix("8a869c63005453c791aca20e62ab42b8ec2501f312f3c81e9e9cb28ef48fe5eaa3403e9db4c37054cc69390335fb9376b7de2cdf0a87cff25d7e54ab733bbaff8f34b4076fc8914f7e66149b04a82d123fe5eefcff6e78f0bfef4c8ded5f55fa5c2a62b6e67231b8918bdf9723778c51417be3ea2e5c546c49a2ebf241fab4cd", 16)!
    dq := big.integer_from_radix("6fcd7c1b840eea5573f94d9c30ab7351a456e4d74adcf6ac8b8b1bf82e5c20d7db19015857a7286a691f2661bbb508ef84e8422d581383d067a6edc5b019e56e974e8e02b06cd0ab230f794bde5e97e59ef677ff77252f2d1d5ae58610a541209de13d75666fbe692863abb0db01cc635fa67e591663b26fefe5ef326e8bb685", 16)!
    q_inv := big.integer_from_radix("a3025ed7af8f1b9536f34fa9cd0f6e647b61bf31017926070b77565b5f2572d9c83003e307749f78a90e5b3bf15df64371ec82308ddf3a39c35501c816fb01ab21632152d71652cb43e2796b47dd29de4511371ec56e760f9d35c14e5e836db3b492866fc401ee59d0e8d64121a55695fc2ef495861c0ca2d42ff54ca622bcb0", 16)!
	pubkey := PublicKey{
        n: n
        e: e.int()
    }
    prikey := PrivateKey{
        PublicKey: pubkey
        d: d
        primes: [p, q]
        precomputed: PrecomputedValues{
            dp: dp
            dq: dq
            q_inv: q_inv
        }
    }

    pubkey12 := prikey.public()
	assert true == pubkey.equal(pubkey12)
	assert 256 == pubkey12.size()

	pubkey2 := PublicKey{
        n: n + big_zero
        e: e.int()
    }
    prikey2 := PrivateKey{
        PublicKey: pubkey2
        d: d + big_zero
        primes: [p + big_zero, q + big_zero]
        precomputed: PrecomputedValues{
            dp: dp + big_zero
            dq: dq + big_zero
            q_inv: q_inv + big_zero
        }
    }
	assert true == prikey.equal(prikey2)

    {
        mut need_err := false
        prikey.validate() or {
            need_err = true
        }

        assert false == need_err
    }

    {
        n2 := big.integer_from_radix("d36c16b5be5229343add228db0f7e0ebe97d789c80ab66cb0bdadc12156fd5dad3447e11d9a2a6ac05337ccdd4143b36555e851ed20a81ce84e5780e91bfe4ee734467c2ed67fd961edf7e3e3a0dc591e19eab6fa662d25fa4655b48b7e635fef30be9a88e709a21248a152143c144c4d5e2a105705862cda613fc2719bd106595d43e4d1f520c5848f2ed96349bc93f49ff72658da96d24fb7c85d53a3771cd6009894f8478fd63c4d7a254c61e139a8c2b33c2b67f5e4798ec99dbb4204a65fa0ea904b5dd7c13819134997ebc85456bb89a27c766d8c2c588391eacef13bbd57221b1198b75a3bb0d28e01b7923de580429033c13c8f302843f56783f01dd", 16)!
        e2 := big.integer_from_radix("010001", 16)!
        d2 := big.integer_from_radix("9dfd71e3127c374a4e8a9d9da0973bbf4f5671e111ce041ccb991b4770398867e3e4950925c784219c2963a4344d820a123575e91830bddbe437ce45a4e8ef5cb94a6ef79d8d4e54f67130d7b36e432bc69c59a42f843d8d373e7ebe929e37cf73347dc175dff36dbcee6ae7d6c80069cf23720cac6d8038095979de863f60960d6164c1011cd1ee736cf8a1daf97d68fceeb86bee283fd5510881ea4bd3e948039ba257cc2079fcc9271b2e872db79d51cf86f15ede905e2f1ed2c56510121a088cb716d23dcd2afda598f3ca11e74af2eb7197de9d1c68d0e4b2d50ed89c3fa806866050aa37091b7d36e0e3195532bd456160e2a66ed7656194b8aabcc089", 16)!
        p2 := big.integer_from_radix("e4220f350412877a994a27cc3fd8bd6e57d8200383dd286bd9fd72a95245321286f3d2b2a9a493a70ca38fd714f7d6f32060d8ade8af0467463377b596d4f5efd6cd52a338764f8f11a8cb4ca00eba3ef9ee4bbb008688879658e409da2db0d74a114d5c5a1b19cabda650544edb9b9a255d6eef0e627a50b5861548e17ae0cb", 16)!
        q2 := big.integer_from_radix("ed3f773a734404fac3793efbe0e6d7277c980e6cd5b3bb5253b32f8d251aabb9bc336789a30dac007828d7a247ec5b4516ba5deb9281746a98ee362b0cc20ba27b7f7b2430215f426c499a9b661e6ef7f6bfb69642642e73f76c489eede2fb3ec3fd11fa1cb0c54ba700fc4a226f77d4dd7a4554ec584ccb7d8c8b3f5da29af7", 16)!
        dp2 := big.integer_from_radix("313c288c0894f7283e6d02a9d21db4c45bb10937b8fdc1fb84d06e2e9cd2d23bad6471d49d482795a5e4a6e6845ff8c3fff8e6caa1ad240625e075b57b17fafc081fc7f5f1f996b209dda402a58888298f471e90fd4c0bab378777afa8a6b3c3c2f878f9b578a3d85d95c7406ac47a9089ffe03137a9893c61f0ce272c829881", 16)!
        dq2 := big.integer_from_radix("18e9cb396615447898c248ace687171cdc66934d367bb33607f80f0c415335a9416c1c7945980ff1d4ac654873490ca48aa87368637018ab80f7b2d47e787a044bf7ad14b5c12b61ac41666cdf225f00c6f686d3ec90dc97ece9800ec0684f7dddd2db6a6a4cddcafdf48a89b668022b663e8abd4a3c538422e0f956641cc92d", 16)!
        q_inv2 := big.integer_from_radix("d13e5c310a6d6af7cf6dd26bbd459769b98e6744796b656189916c453126b1284e612c89c66f50f3f081cd9d067f0317a09c003de46cf1fb226223e77d71a72f87e651f93d40623002fa54a3f95f9ca1665b48048136f097cd97d11b32f5bd89c7cef0080df747af0c7d3c134ce98cb6802a1e21a02892b5125a06345364756e", 16)!
        prikey3 := PrivateKey{
            PublicKey: PublicKey{
                n: n2
                e: e2.int()
            }
            d: d2
            primes: [p2, q2]
            precomputed: PrecomputedValues{
                dp: dp2
                dq: dq2
                q_inv: q_inv2
            }
        }

        assert false == prikey.equal(prikey3)
    }
}

fn test_private_key_precompute() {
    n := big.integer_from_radix("9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767", 16)!
    e := big.integer_from_radix("010001", 16)!
    d := big.integer_from_radix("63d392db30747f975f948ddd0e4205a43d743e8b775a1a670a55673b087ca0f0a7c1edc9ed97d5ffd852a02c53109a95ac4feff9f4ce38c7f7109939e99ac98b746ebde3faa182d07e73e754955da8cfb1f44f6e66363bbb0436c0b331e58d9d6a1c45ee3543f75e57d3aba8a89edf6a602235a01fa3afbce49b9632159faa70b570ac22d54af63e1c2f09869d91a0a4cbe4f2f4f0ba6c7469df09a1a121b7044df20b0e90089ae1e4d194bd72c85ead2db6de51b69961b0454b2ed3ac0ed9c1cd75dac818a6cb2d47ec0d950907ad14d68812b4ec83766795369c81fa10eab57c9774bf83f2d9eebc5f96c58d0a864bf005b905cf26deda7c5220754e2ee2b9", 16)!
    p := big.integer_from_radix("cc558bc7e22c34a9b5012f75ed39ccb284f2f4a64af78652b5cb6f77999202344161192ae63a5cd048d1943b80b98a66e15142187efc2d471f0f7d258843790d87b190a2a522a299b3b8ccf1d250b3003394d29ff6a9a79bbf9b08219d45969147dad74b44ad223adbebf48a2a0dd9ad394a8838fc8bbadc7025001663e4b46b", 16)!
    q := big.integer_from_radix("c4c5b893ac7215a18383cba6b27bb4e0f8a7890649da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5", 16)!

    c1 := big.integer_from_radix("c4c5b893ac7215a18383cba6b27bb4e0f8a7890647da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f5", 16)!
    c2 := big.integer_from_radix("c4c5b893ac7215a18383cba6b27bb4e0f8a7890647da0c26c317d1703c16ae7f875686002f840857d814d75ada28b7ac54e3b7a1db6af3a8b67b780beb90a32f80eebb839bdeecf309faca921dd00aeb359aa4b1b93c0357df1c52dcd992548f6739b243630a6149293f8480d38b6ce2b4d603dc5d9d21914a08e3cf020067f8", 16)!
    
    mut prikey := PrivateKey{
        PublicKey: PublicKey{
            n: n
            e: e.int()
        }
        d: d
        primes: [p, q, c1, c2]
    }

    prikey.precompute()!

	assert 256 == prikey.size()

    dp := "8a869c63005453c791aca20e62ab42b8ec2501f312f3c81e9e9cb28ef48fe5eaa3403e9db4c37054cc69390335fb9376b7de2cdf0a87cff25d7e54ab733bbaff8f34b4076fc8914f7e66149b04a82d123fe5eefcff6e78f0bfef4c8ded5f55fa5c2a62b6e67231b8918bdf9723778c51417be3ea2e5c546c49a2ebf241fab4cd"
    dq := "6fcd7c1b840eea5573f94d9c30ab7351a456e4d74adcf6ac8b8b1bf82e5c20d7db19015857a7286a691f2661bbb508ef84e8422d581383d067a6edc5b019e56e974e8e02b06cd0ab230f794bde5e97e59ef677ff77252f2d1d5ae58610a541209de13d75666fbe692863abb0db01cc635fa67e591663b26fefe5ef326e8bb685"
    q_inv := "a3025ed7af8f1b9536f34fa9cd0f6e647b61bf31017926070b77565b5f2572d9c83003e307749f78a90e5b3bf15df64371ec82308ddf3a39c35501c816fb01ab21632152d71652cb43e2796b47dd29de4511371ec56e760f9d35c14e5e836db3b492866fc401ee59d0e8d64121a55695fc2ef495861c0ca2d42ff54ca622bcb0"

	assert dp == prikey.precomputed.dp.hex()
	assert dq == prikey.precomputed.dq.hex()
	assert q_inv == prikey.precomputed.q_inv.hex()

	assert 2 == prikey.precomputed.crt_values.len

    exp := "72947fe11cb8f4d7a3a6693b74cd27747e00221eaa2413e44340e7c1906ce71367e644be9e2d7bc9d9aa25da168a4ce7b7ad3cf45d39abbab55571da1d11634a2c645fa6038b61822b037a02e76bcdbfc8c497b47b863b485b270b46c520262204e8f000873e95efee8a9235b7a628feef36feb93adba8d882f0a0060ee95b19"
    coeff := "24866ea0c2869d06893e642a5f1f39a5b4cb050bd69dae13387bb7c2aa56344fc527708de0cad92eaa2e22f5f1c2fc7049e2d3cfa65dabea73c9fc2dac9fb2e3d72bff9030b2ae0b0cc7664478a9adb3bf05b106f9c586dbdd996006a15a58e69950c17f264d43984bf1c62f988554dcfaf736e53db4f921779dca67c95eabd6"
    r := "9d0f502cf5365bf3949f1bfaa444fa9c9fd0f9126e2d86a753f276e5d5ff813be4f33b88603a6e569b83a363cbb17e0e7c1dd86bc067b9955eec933e08ab75dba44b758a95439e327087d4d5e017c8f79da4d7c7d694ec397fbfeb04a7ee265af15407db70b840aacc03703dc74bf48707f00e781536bf971b61d38d5825838ebd4bed1db8b3f508e15e2e622839b3b0e1fe051b51b2834801df59131e11e7e8cf2120173f4254b9e5a3cab2dcb14f6d4abf087e58876b880eb1d488af21bf80e565939afd08a3ba046444180a955d1f19a40bb51ebcd2a4178df97ee9cf8f145d13d84eef37ea61577e65de80271a3dfc2fbbca2dc5f3ac867aa48c7477b767"

    crt_values1 := prikey.precomputed.crt_values[0]
	assert exp == crt_values1.exp.hex()
	assert coeff == crt_values1.coeff.hex()
	assert r == crt_values1.r.hex()

    exp2 := "7680dbd54fc851285c0ee3834e88a4e37865d19a3d82ac12f9338147c190b6af4ccb3b8f72cdbb93f3adeb8af464ed7bb1638bd4349dc96dc4295d164287608b0870fae8308b7cb6c22109cc60dcbb31be76ce23ac22e4a44f9eacab6c3f83cfdee50a980f9ee8094e5e43336305191494fd029ee1774c7a47b6b7ed3656bcef"
    coeff2 := "5512624023ed5ef4f7b4a4f2c159a73075a6e45cf56dabfe654b7e65b7c701e1a9119d7a0fd285f79072f838be82285c7076802ff5f1817ae1a1905d0920c48905db7e4212d51745ce775b48558adea4e1a13cd41aba042a8af3942e3265e93ccb72ec55074d75afa30cadf5ddedf74c57d38254e813895af3b0f82f2f699f3b"
    r2 := "78b90768b98df340623395bbdaaacf866f405b94e51b8a53f1586d576ef603bd97bb07ca8e439ffbf9b2276acce1985c12224f7b31041b880fc0a9fe0ddb076feb0139056cd82af5a5c5eb13630976f94486d5e0c51021ba4ecfddf58d972911164659610639bb0ad1c7acd138802ca1fbd0ecd3f8892bdaddf4efb2735f19d4b3903ed1767ba94e719e46b9794a484f16386e76bfb9802a28bc63e6dd1ed6c60f86c993d10a81e9fbcc7631501e32a0348049000b76d176b8efc250b3bb2828ec5adcd92fec125837a9c30811aa7cadc57eeacc51c82e67d4ea1d45efd97aaed198c23c123fd2ec067c98fafa034c3fd1eb1f879fc1bc06c26c1dbf110d18593afc32238db74f01f6e66d132517bff2178f14ff58ffe54bab1e020e99efe61c48f06ac1583cbc5cd1a8e95a817319f785d290674ddba2c57cd1c58c36192f8dfdc2e3ee94171fc494176d1a0de940c235ea4c3ae5dfaaad838591016088c666e82a5e88a4b65a75cb01e96a176b70054e40531653499371fa228dff6f5cf693"

    crt_values2 := prikey.precomputed.crt_values[1]
	assert exp2 == crt_values2.exp.hex()
	assert coeff2 == crt_values2.coeff.hex()
	assert r2 == crt_values2.r.hex()

}

