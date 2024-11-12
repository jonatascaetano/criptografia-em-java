package com.jonatas.criptografia;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

public class DigitalSignature {

	public static String create(String message, PrivateKey privateKey)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(message.getBytes());
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(hash);
		byte[] digitalSignature = signature.sign();
		String encodedSignature = Base64.getEncoder().encodeToString(digitalSignature);
		return encodedSignature;
	}

	public static boolean check(String message, String encodedSignature, PublicKey publicKey)
			throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] hash = digest.digest(message.getBytes());
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey);
		signature.update(hash);
		byte[] digitalSignature = Base64.getDecoder().decode(encodedSignature);
		boolean isVerified = signature.verify(digitalSignature);
		System.out.println("Assinatura verificada: " + isVerified);
		return isVerified;
	}
}
