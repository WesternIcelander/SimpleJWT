package io.siggi.simplejwt.alg;

import java.security.PrivateKey;
import java.security.PublicKey;

public class RS512 extends RS {
	public RS512(PrivateKey privateKey, PublicKey publicKey) {
		super(privateKey, publicKey, "SHA512withRSA", "RS512");
	}

	public RS512(PublicKey publicKey) {
		this(null, publicKey);
	}
}
