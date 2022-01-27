package io.siggi.simplejwt.alg;

import io.siggi.simplejwt.JWTToken;
import io.siggi.simplersa.RSA;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RS extends JWTAlgorithm {
	private final PrivateKey privateKey;
	private final PublicKey publicKey;
	private final String hashingAlgorithm;
	private final String algName;
	RS(PrivateKey privateKey, PublicKey publicKey, String hashingAlgorithm, String algName) {
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.hashingAlgorithm = hashingAlgorithm;
		this.algName = algName;
	}

	@Override
	public boolean canSign() {
		return privateKey != null;
	}

	@Override
	public boolean canVerify() {
		return publicKey != null;
	}

	@Override
	public JWTToken sign(String payload) {
		if (privateKey == null)
			throw new UnsupportedOperationException("No private key available.");
		String signedData = generateSignedData(algName, payload);
		byte[] signedDataBytes = signedData.getBytes(StandardCharsets.UTF_8);
		byte[] signature = RSA.sign(signedDataBytes, privateKey, hashingAlgorithm);
		return JWTToken.parse(signedData + "." + base64Encode(signature));
	}

	@Override
	public boolean verify(JWTToken token) {
		if (publicKey == null)
			throw new UnsupportedOperationException("No public key available.");
		return RSA.verify(token.getSignedPart().getBytes(StandardCharsets.UTF_8), publicKey, token.getSignature(), hashingAlgorithm);
	}
}
