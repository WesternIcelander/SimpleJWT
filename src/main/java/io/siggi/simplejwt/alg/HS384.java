package io.siggi.simplejwt.alg;

public class HS384 extends HS {
	public HS384(byte[] secret) {
		super(secret, "HmacSHA384", "HS384");
	}
}
