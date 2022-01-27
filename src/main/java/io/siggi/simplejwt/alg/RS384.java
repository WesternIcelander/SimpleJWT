package io.siggi.simplejwt.alg;

import java.security.PrivateKey;
import java.security.PublicKey;

public class RS384 extends RS {
	public RS384(PrivateKey privateKey, PublicKey publicKey) {
		super(privateKey, publicKey, "SHA384withRSA", "RS384");
	}

	public RS384(PublicKey publicKey) {
		this(null, publicKey);
	}
}
