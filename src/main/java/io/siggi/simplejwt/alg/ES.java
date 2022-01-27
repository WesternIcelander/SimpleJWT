package io.siggi.simplejwt.alg;

import io.siggi.simpleecdsa.ECDSASignature;
import io.siggi.simpleecdsa.SimpleECDSA;
import io.siggi.simplejwt.JWTToken;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class ES extends JWTAlgorithm {
	private final ECPublicKey publicKey;
	private final ECPrivateKey privateKey;
	private final SimpleECDSA ecdsa;
	private final String hashingAlgorithm;
	private final String algName;

	public ES(byte[] secret, String curve, String hashingAlgorithm, String algName) {
		try {
			ecdsa = SimpleECDSA.getCurve(curve);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		int bytes = ecdsa.getBytes();
		if (secret.length == bytes) {
			privateKey = ecdsa.getPrivate(secret);
			publicKey = ecdsa.getPublic(privateKey);
		} else if (secret.length == bytes * 2 || secret.length == (bytes * 2) + 1) {
			privateKey = null;
			publicKey = ecdsa.getPublic(secret);
		} else {
			throw new IllegalArgumentException("Invalid secret");
		}
		this.hashingAlgorithm = hashingAlgorithm;
		this.algName = algName;
	}

	public boolean canSign() {
		return privateKey != null;
	}

	public boolean canVerify() {
		return true;
	}

	@Override
	public JWTToken sign(String payload) {
		if (privateKey == null)
			throw new UnsupportedOperationException("No private key available.");
		String signedData = generateSignedData(algName, payload);
		byte[] signedDataBytes = signedData.getBytes(StandardCharsets.UTF_8);
		byte[] hash = hash(signedDataBytes);
		String signature = base64Encode(ecdsa.sign(privateKey, hash).toRS());
		return JWTToken.parse(signedData + "." + signature);
	}

	@Override
	public boolean verify(JWTToken token) {
		byte[] hash = hash(token.getSignedPart().getBytes(StandardCharsets.UTF_8));
		ECDSASignature signature = ECDSASignature.fromRS(ecdsa, token.getSignature());
		return ecdsa.verify(publicKey, hash, signature);
	}

	private byte[] hash(byte[] data) {
		try {
			MessageDigest md = MessageDigest.getInstance(hashingAlgorithm);
			md.update(data);
			return md.digest();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
