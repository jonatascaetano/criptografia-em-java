package com.jonatas.criptografia;

import java.security.PrivateKey;
import java.security.PublicKey;

import com.jonatas.criptografia.model.AESEncoderLongModel;
import com.jonatas.criptografia.model.AESEncoderModel;
import com.jonatas.criptografia.model.RSAKeysModel;

public class App {

	public static void main(String[] args) {

		try {
			RSAKeysModel rsaKeysModel = GenerateKeyPair.generate();

			System.out.println("Chave Pública: " + rsaKeysModel.publicKey());
			System.out.println("Chave Privada: " + rsaKeysModel.privateKey());

			PublicKey publicKey = ConvertKeys.decodePublicKey(rsaKeysModel.publicKey());
			PrivateKey privateKey = ConvertKeys.decodePrivateKey(rsaKeysModel.privateKey());

			String msg = "Acredite em si mesmo e em todo o seu potencial. Saiba que você é capaz de realizar qualquer coisa que decidir fazer. - Autor Desconhecido";

			String msgEncode = RSAEncryptionDecryption.encryptMessage(msg, publicKey);

			System.out.println(msgEncode);

			String msgDecode = RSAEncryptionDecryption.decryptMessage(msgEncode, privateKey);

			System.out.println(msgDecode);

			AESEncoderModel easEncoderModel = AESEncryptionDecryption.encryptMessage(msgDecode, publicKey);
			System.out.println("chave criptografada eas: " + easEncoderModel.encodedEncryptedAesKey());
			System.out.println("mensagem criptografada eas: " + easEncoderModel.encodedEncryptedMessage());

			String msgDecodeEAS = AESEncryptionDecryption.decryptMessage(easEncoderModel.encodedEncryptedMessage(),
					easEncoderModel.encodedEncryptedAesKey(), privateKey);

			System.out.println("mensagem decriptografada eas: " + msgDecodeEAS);

			String historia = "Era uma vez um cãozinho chamado Pipo.\r\n" + "\r\n"
					+ "Ele era muito curioso e adorava explorar novos lugares. \r\n" + "\r\n"
					+ "Um dia, Pipo decidiu sair da casinha e se aventurar pela floresta.\r\n" + "\r\n"
					+ "Ele pulou por entre as árvores e encontrou animais diferentes.\r\n" + "\r\n"
					+ "Fez amizade com o macaco, o coelho e até um bicho preguiça dorminhoco.\r\n" + "\r\n"
					+ "O macaco, muito falante, disse para Pipo:\r\n" + "\r\n"
					+ "“Pipo, a floresta é muito bonita, mas para quem não a conhece, ela pode ser perigosa também”.\r\n"
					+ "\r\n" + "O coelho, sempre muito esperto, acrescentou:\r\n" + "\r\n"
					+ "“É verdade! Ontem mesmo a onça quase me pegou!”\r\n" + "\r\n"
					+ "A conversa estava tão animada que até a preguiça resolveu falar:\r\n" + "\r\n"
					+ "“Cuidado Pipo…não fique na floresta à noite… zzzzz”\r\n" + "\r\n"
					+ "Para a sorte de Pipo, estava por perto uma coruja sábia que o ajudou a encontrar o caminho de volta para casa. \r\n"
					+ "\r\n"
					+ "Ao retornar, Pipo percebeu que a aventura era emocionante, mas também valorizou o conforto e a segurança de seu lar.\r\n"
					+ "\r\n"
					+ "Ele aprendeu que é legal sair de casa de vez em quando, desde que com autorização dos pais e voltando cedo.";

			AESEncoderLongModel aesEncoderLongModel = AESEncryptionDecryption.encryptMessageLong(historia, publicKey);

			System.out.println("long - chave criptografada aes: " + aesEncoderLongModel.encodedEncryptedAesKey());
			System.out.println("long - iv criptografado: " + aesEncoderLongModel.encodedIV());
			System.out.println("long - mensagem criptografada aes: " + aesEncoderLongModel.encryptedMessage());

			String historiaDecriptografada = AESEncryptionDecryption.decryptMessageLong(
					aesEncoderLongModel.encryptedMessage(), aesEncoderLongModel.encodedEncryptedAesKey(),
					aesEncoderLongModel.encodedIV(), privateKey);

			System.out.println("historiaDecriptografada: " + historiaDecriptografada);

			String encodedSignature = DigitalSignature.create(aesEncoderLongModel.encryptedMessage(), privateKey);
			DigitalSignature.check(aesEncoderLongModel.encryptedMessage(), encodedSignature, publicKey);

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
