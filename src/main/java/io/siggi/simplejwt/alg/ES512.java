package io.siggi.simplejwt.alg;

public class ES512 extends ES {
	public ES512(byte[] secret) {
		super(secret, "secp521r1", "SHA512", "ES512");
	}
}
