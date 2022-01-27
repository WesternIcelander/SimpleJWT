package io.siggi.simplejwt.alg;

public class ES256 extends ES {
	public ES256(byte[] secret) {
		super(secret, "secp256r1", "SHA256", "ES256");
	}
}
