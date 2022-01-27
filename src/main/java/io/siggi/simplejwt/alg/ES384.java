package io.siggi.simplejwt.alg;

public class ES384 extends ES {
	public ES384(byte[] secret) {
		super(secret, "secp384r1", "SHA384", "ES384");
	}
}
