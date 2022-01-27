package io.siggi.simplejwt.alg;

import com.google.gson.JsonObject;
import io.siggi.simplejwt.JWTToken;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public abstract class JWTAlgorithm {
	private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder();

	protected static String base64Encode(byte[] data) {
		return base64Encoder.encodeToString(data).replace("=", "");
	}

	public abstract boolean canSign();

	public abstract boolean canVerify();

	public abstract JWTToken sign(String payload);

	public abstract boolean verify(JWTToken token);

	public final boolean verify(String token) {
		return verify(JWTToken.parse(token));
	}

	private final Map<String, String> headerFields = new HashMap<>();

	public final void setHeaderField(String key, String value) {
		if (key == null) throw new NullPointerException();
		if (key.equals("alg")) {
			throw new IllegalArgumentException(key + " cannot be overridden");
		}
		if (value == null) {
			headerFields.remove(key);
		} else {
			headerFields.put(key, value);
		}
	}

	protected final String generateSignedData(String algName, String payload) {
		JsonObject object = new JsonObject();
		object.addProperty("alg", algName);
		for (Map.Entry<String, String> entry : headerFields.entrySet()) {
			object.addProperty(entry.getKey(), entry.getValue());
		}
		String header = object.toString();
		return base64Encoder.encodeToString(header.getBytes(StandardCharsets.UTF_8)).replace("=", "")
				+ "." + base64Encoder.encodeToString(payload.getBytes(StandardCharsets.UTF_8)).replace("=", "");
	}
}
