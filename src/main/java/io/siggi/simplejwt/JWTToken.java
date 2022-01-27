package io.siggi.simplejwt;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.UUID;

public final class JWTToken {
	private static final Base64.Decoder decoder = Base64.getUrlDecoder();
	private final String originalToken;
	private final String headerString;
	private final JsonObject header;
	private final String payloadString;
	private final JsonObject payload;
	private final String signatureString;
	private final byte[] signature;

	private JWTToken(String token) {
		this.originalToken = token;
		String[] tokenParts = token.split("\\.");
		if (tokenParts.length != 3) {
			throw new IllegalArgumentException("Invalid JWT token");
		}
		try {
			headerString = new String(decoder.decode(tokenParts[0]), StandardCharsets.UTF_8);
			payloadString = new String(decoder.decode(tokenParts[1]), StandardCharsets.UTF_8);
			signatureString = tokenParts[2];
			signature = decoder.decode(tokenParts[2]);
			header = JsonParser.parseString(headerString).getAsJsonObject();
			JsonObject payloadObj;
			try {
				payloadObj = JsonParser.parseString(payloadString).getAsJsonObject();
			} catch (Exception e) {
				payloadObj = null;
			}
			payload = payloadObj;
		} catch (Exception e) {
			throw new IllegalArgumentException("Invalid JWT token");
		}
	}

	/**
	 * Parse a JWT token.
	 *
	 * @param token the token in string form
	 * @return a JWTToken
	 * @throws IllegalArgumentException if the token is not valid.
	 */
	public static JWTToken parse(String token) {
		return new JWTToken(token);
	}

	/**
	 * Get the algorithm used to sign this token.
	 *
	 * @return the signing algorithm.
	 */
	public String getAlgorithm() {
		return getHeaderValue("alg");
	}

	/**
	 * Check if this the passed epoch time is within the validity period of this token.
	 *
	 * @param epochTimeInSeconds The time to check
	 * @return true if the passed time is within the validity period, false otherwise.
	 */
	public boolean isValid(long epochTimeInSeconds) {
		long notBefore = getLongValue("nbf");
		if (notBefore != 0L && epochTimeInSeconds < notBefore) {
			return false;
		}
		long expires = getLongValue("exp");
		if (expires != 0L && epochTimeInSeconds >= expires) {
			return false;
		}
		return true;
	}

	public String getHeaderValue(String key) {
		JsonElement value = header.get(key);
		if (key == null || !value.isJsonPrimitive())
			return null;
		return value.getAsString();
	}

	public String getValue(String key) {
		JsonElement value = payload.get(key);
		if (value == null || !value.isJsonPrimitive())
			return null;
		return value.getAsString();
	}

	// <editor-fold desc="Non-string getters" defaultstate="collapsed">
	public UUID getUuidValue(String key) {
		JsonElement value = payload.get(key);
		if (value == null || !value.isJsonPrimitive())
			return null;
		try {
			return UUID.fromString(value.getAsString().replace("-", "").replaceAll("([0-9A-Fa-f]{8})([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})([0-9A-Fa-f]{12})", "$1-$2-$3-$4-$5"));
		} catch (Exception e) {
			return null;
		}
	}

	public int getIntValue(String key) {
		JsonElement value = payload.get(key);
		if (value == null || !value.isJsonPrimitive())
			return 0;
		return value.getAsInt();
	}

	public long getLongValue(String key) {
		JsonElement value = payload.get(key);
		if (value == null || !value.isJsonPrimitive())
			return 0L;
		return value.getAsLong();
	}

	public float getFloatValue(String key) {
		JsonElement value = payload.get(key);
		if (value == null || !value.isJsonPrimitive())
			return 0.0f;
		return value.getAsLong();
	}

	public double getDoubleValue(String key) {
		JsonElement value = payload.get(key);
		if (value == null || !value.isJsonPrimitive())
			return 0.0;
		return value.getAsDouble();
	}

	public boolean getBooleanValue(String key) {
		JsonElement value = payload.get(key);
		if (value == null || !value.isJsonPrimitive())
			return false;
		return value.getAsBoolean();
	}
	// </editor-fold>

	public JsonObject getHeader() {
		return JsonParser.parseString(headerString).getAsJsonObject();
	}

	public String getHeaderString() {
		return headerString;
	}

	public JsonObject getPayload() {
		if (payload == null)
			return null;
		return JsonParser.parseString(payloadString).getAsJsonObject();
	}

	public String getPayloadString() {
		return payloadString;
	}

	public byte[] getSignature() {
		return Arrays.copyOf(signature, signature.length);
	}

	public String getSignatureString() {
		return signatureString;
	}

	public String getSignedPart() {
		return headerString + "." + payloadString;
	}

	public String toString() {
		return originalToken;
	}
}
