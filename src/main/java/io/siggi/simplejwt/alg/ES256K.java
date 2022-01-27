package io.siggi.simplejwt.alg;

public class ES256K extends ES {
	public ES256K(byte[] secret) {
		super(secret, "secp256k1", "SHA256", "ES256K");
	}
}
