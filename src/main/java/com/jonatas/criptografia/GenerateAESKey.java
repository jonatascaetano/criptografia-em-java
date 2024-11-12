package com.jonatas.criptografia;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class GenerateAESKey {

	public static SecretKey generate() throws NoSuchAlgorithmException{
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		SecretKey aesKey = keyGen.generateKey();		
		return aesKey;
	}
}
