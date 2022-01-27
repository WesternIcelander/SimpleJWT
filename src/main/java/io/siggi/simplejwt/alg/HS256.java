package io.siggi.simplejwt.alg;

public class HS256 extends HS {
	public HS256(byte[] secret) {
		super(secret, "HmacSHA256", "HS256");
	}
}
