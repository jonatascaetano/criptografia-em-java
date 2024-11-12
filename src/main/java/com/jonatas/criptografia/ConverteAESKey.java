package com.jonatas.criptografia;

import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ConverteAESKey {

	public static String encodeKey(SecretKey aesKey) throws Exception {

		byte[] aesKeyBytes = aesKey.getEncoded();

		String base64EncodedKey = Base64.getEncoder().encodeToString(aesKeyBytes);

		System.out.println("Chave AES (Base64): " + base64EncodedKey);

		return base64EncodedKey;
	}

	public static SecretKeySpec decodeKey(String Key) throws Exception {

		String base64EncodedKey = "SuaChaveAESBase64Aqui";

		byte[] decodedKey = Base64.getDecoder().decode(base64EncodedKey);

		SecretKeySpec aesKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

		System.out.println("Chave AES: " + aesKey);

		return aesKey;
	}

}
