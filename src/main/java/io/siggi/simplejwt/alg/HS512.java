package io.siggi.simplejwt.alg;

public class HS512 extends HS {
	public HS512(byte[] secret) {
		super(secret, "HmacSHA512", "HS512");
	}
}
