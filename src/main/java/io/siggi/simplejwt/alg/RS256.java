package io.siggi.simplejwt.alg;

import java.security.PrivateKey;
import java.security.PublicKey;

public class RS256 extends RS {
	public RS256(PrivateKey privateKey, PublicKey publicKey) {
		super(privateKey, publicKey, "SHA256withRSA", "RS256");
	}

	public RS256(PublicKey publicKey) {
		this(null, publicKey);
	}
}
