package com.jonatas.criptografia;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import com.jonatas.criptografia.model.RSAKeysModel;

public class GenerateKeyPair {
	public static RSAKeysModel generate() throws NoSuchAlgorithmException {
		try {

			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");

			keyPairGen.initialize(2048);

			KeyPair pair = keyPairGen.generateKeyPair();

			PublicKey publicKey = pair.getPublic();

			PrivateKey privateKey = pair.getPrivate();

			String publicKeyEncode = ConvertKeys.encodePublicKey(publicKey);
			String privateKeyEncode = ConvertKeys.encodePrivateKey(privateKey);

			return new RSAKeysModel(privateKeyEncode, publicKeyEncode);

		} catch (NoSuchAlgorithmException e) {
			throw e;
		} catch (Exception e) {
			throw e;
		}
	}
}
