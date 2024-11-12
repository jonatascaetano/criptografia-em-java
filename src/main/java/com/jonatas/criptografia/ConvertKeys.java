package com.jonatas.criptografia;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ConvertKeys {

	public static PublicKey decodePublicKey(String base64Key) throws Exception {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] decodedPublicKey = Base64.getDecoder().decode(base64Key);
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decodedPublicKey);
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
			return publicKey;
		} catch (Exception e) {
			throw e;
		}
	}

	public static PrivateKey decodePrivateKey(String base64Key) throws Exception {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] decodedPrivateKey = Base64.getDecoder().decode(base64Key);
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decodedPrivateKey);
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			return privateKey;
		} catch (Exception e) {
			throw e;
		}
	}

	public static String encodePublicKey(PublicKey publicKey) {
		String key = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		return key;
	}

	public static String encodePrivateKey(PrivateKey privateKey) {
		String key = Base64.getEncoder().encodeToString(privateKey.getEncoded());
		return key;
	}

}
