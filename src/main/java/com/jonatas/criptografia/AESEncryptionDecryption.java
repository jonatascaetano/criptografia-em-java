package com.jonatas.criptografia;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.jonatas.criptografia.model.AESEncoderLongModel;
import com.jonatas.criptografia.model.AESEncoderModel;

public class AESEncryptionDecryption {

	public static AESEncoderModel encryptMessage(String message, PublicKey publicKey) throws Exception {

		SecretKey aesKey = GenerateAESKey.generate();

		Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
		byte[] encryptedMessageBytes = aesCipher.doFinal(message.getBytes());

		Cipher rsaCipher = Cipher.getInstance("RSA");
		rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());

		String encodedEncryptedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);
		String encodedEncryptedAesKey = Base64.getEncoder().encodeToString(encryptedAesKey);

		return new AESEncoderModel(encodedEncryptedMessage, encodedEncryptedAesKey);
	}

	public static String decryptMessage(String encryptedMessage, String encodedEncryptedAesKey, PrivateKey privateKey)
			throws Exception {
		byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedMessage);
		byte[] encryptedAesKey = Base64.getDecoder().decode(encodedEncryptedAesKey);

		Cipher rsaCipher = Cipher.getInstance("RSA");
		rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
		SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

		Cipher aesCipher = Cipher.getInstance("AES");
		aesCipher.init(Cipher.DECRYPT_MODE, aesKey);
		byte[] decryptedMessageBytes = aesCipher.doFinal(encryptedMessageBytes);
		String decryptedMessage = new String(decryptedMessageBytes);

		return decryptedMessage;
	}

	public static AESEncoderLongModel encryptMessageLong(String message, PublicKey publicKey) throws Exception {

		SecretKey aesKey = GenerateAESKey.generate();

		byte[] iv = new byte[16];
		new java.security.SecureRandom().nextBytes(iv);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);

		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		aesCipher.init(Cipher.ENCRYPT_MODE, aesKey, ivSpec);
		byte[] encryptedMessageBytes = aesCipher.doFinal(message.getBytes());
		
		String encryptedMessage = Base64.getEncoder().encodeToString(encryptedMessageBytes);
		String encodedIV = Base64.getEncoder().encodeToString(iv);

		Cipher rsaCipher = Cipher.getInstance("RSA");
		rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedAesKey = rsaCipher.doFinal(aesKey.getEncoded());
		String encodedEncryptedAesKey = Base64.getEncoder().encodeToString(encryptedAesKey);
		
		return new AESEncoderLongModel(encryptedMessage, encodedIV, encodedEncryptedAesKey);
	}

	public static String decryptMessageLong(String encryptedMessage, String encodedEncryptedAesKey, String encodedIV,
			PrivateKey privateKey) throws Exception {

		byte[] encryptedAesKey = Base64.getDecoder().decode(encodedEncryptedAesKey);
		Cipher rsaCipher = Cipher.getInstance("RSA");
		rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] aesKeyBytes = rsaCipher.doFinal(encryptedAesKey);
		SecretKeySpec aesKey = new SecretKeySpec(aesKeyBytes, "AES");

		byte[] iv = Base64.getDecoder().decode(encodedIV);
		IvParameterSpec ivSpec = new IvParameterSpec(iv);

		byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedMessage);
		Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		aesCipher.init(Cipher.DECRYPT_MODE, aesKey, ivSpec);
		byte[] decryptedMessageBytes = aesCipher.doFinal(encryptedMessageBytes);
		return new String(decryptedMessageBytes);

	}

}
