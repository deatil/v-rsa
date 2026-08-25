module rsa

pub struct ErrDecryption {
	Error
}

pub fn (e ErrDecryption) msg() string {
	return 'v-rsa: decryption error'
}

pub struct ErrVerification {
	Error
}

pub fn (e ErrVerification) msg() string {
	return 'v-rsa: verification error'
}

pub struct ErrMessageTooLong {
	Error
}

pub fn (e ErrMessageTooLong) msg() string {
	return 'v-rsa: message too long for RSA public key size'
}
