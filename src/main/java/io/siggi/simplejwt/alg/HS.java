package io.siggi.simplejwt.alg;

import io.siggi.simplejwt.JWTToken;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

class HS extends JWTAlgorithm {
	private final byte[] secret;
	private final String hashingAlgorithm;
	private final String algName;

	HS(byte[] secret, String hashingAlgorithm, String algName) {
		this.secret = Arrays.copyOf(secret, secret.length);
		this.hashingAlgorithm = hashingAlgorithm;
		this.algName = algName;
	}

	@Override
	public boolean canSign() {
		return true;
	}

	@Override
	public boolean canVerify() {
		return true;
	}

	@Override
	public JWTToken sign(String payload) {
		String signedData = generateSignedData(algName, payload);
		byte[] signedDataBytes = signedData.getBytes(StandardCharsets.UTF_8);
		byte[] hash = hash(signedDataBytes);
		return JWTToken.parse(signedData + "." + (base64Encode(hash)));
	}

	@Override
	public boolean verify(JWTToken token) {
		String expectedSignature = base64Encode(hash(token.getSignedPart().getBytes(StandardCharsets.UTF_8)));
		return token.getSignatureString().equals(expectedSignature);
	}

	private byte[] hash(byte[] data) {
		try {
			Mac hmac = Mac.getInstance(hashingAlgorithm);
			hmac.init(new SecretKeySpec(secret, hashingAlgorithm));
			return hmac.doFinal(data);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
