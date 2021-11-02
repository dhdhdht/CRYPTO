package asymmetric;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;

import javax.crypto.Cipher;

public class Rsa2048Map {
	
//	//@Test
	public static void main(String[] args) throws GeneralSecurityException {
		HashMap<String, String> rsaKeyPair = generateKeyPair();
		String publicKey = rsaKeyPair.get("publicKey");
		String privateKey = rsaKeyPair.get("privateKey");
		System.out.println("key : " + publicKey);
		System.out.println("key2 : " + privateKey);
		
		String text = "안녕하세요";
		System.out.println("평문 : " + text);
		
		String encrypt = rsaEncrypt(text, publicKey);
		System.out.println("암호화 : " + encrypt);
		
		String decrypt = rsaDecrypt(encrypt, privateKey);
		System.out.println("복호화 : " + decrypt);
		
		System.out.println("서명 데이터 :  " + text);
		String signature = rsaSign(privateKey, text.getBytes());
		System.out.println("서명문 : " + signature);
		boolean verified = rsaVerify(publicKey, signature, text.getBytes());
		System.out.println("검증결과 : " + verified);
	}
	
	//키 쌍 생성
	public static HashMap<String, String> generateKeyPair() throws GeneralSecurityException {
		HashMap<String, String> stringKeypair = new HashMap<>();
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(2048);
			KeyPair pair = generator.generateKeyPair();
			
			PublicKey publicKey = pair.getPublic();
			PrivateKey privateKey = pair.getPrivate();
			
			//key base64로 인코딩
			String stringPubKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
			String stringPriKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
			
			stringKeypair.put("publicKey", stringPubKey);
			stringKeypair.put("privateKey", stringPriKey);
			
		}catch(Exception e) {
			e.printStackTrace();
		}
		
		return stringKeypair;
	}
	
	
	//암호화 (return base64)
	public static String rsaEncrypt(String plainData, String stringPubKey) {
		String encryptData = null;
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] bytePublicKey = Base64.getDecoder().decode(stringPubKey.getBytes());
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
			
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			
			byte[] byteEncryptData = cipher.doFinal(plainData.getBytes());
			encryptData = Base64.getEncoder().encodeToString(byteEncryptData);
			
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return encryptData;
	}
	
	//복호화 (return base64)
	public static String rsaDecrypt(String encryptData, String stringPriKey) {
		String decryptData = null;
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] bytePrivateKey = Base64.getDecoder().decode(stringPriKey.getBytes());
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			
			byte[] byteEncryptData = Base64.getDecoder().decode(encryptData.getBytes());
			byte[] byteDecryptData = cipher.doFinal(byteEncryptData);
//			decryptData = new String(byteDecryptData);
			decryptData = Base64.getEncoder().encodeToString(byteDecryptData);
			
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return decryptData;
	}
	
	//전자서명
	public static String rsaSign(String stringPriKey, byte[] plainData) throws GeneralSecurityException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		//인코딩된 개인키 개인키객체로 변환
		byte[] bytePrivateKey = Base64.getDecoder().decode(stringPriKey.getBytes());
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(plainData);
		byte[] signatureData = signature.sign();
		String result = Base64.getEncoder().encodeToString(signatureData);
		
		return result;
	}
	
	//전자서명 검증
	public static boolean rsaVerify(String stringPubKey, String signData, byte[] plainData) throws GeneralSecurityException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		//인코딩된 공개키 공개키객체로 변환
		byte[] bytePublicKey = Base64.getDecoder().decode(stringPubKey.getBytes());
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		
		//인코딩된 signData 디코딩
		byte[] signatureData = Base64.getDecoder().decode(signData);
		
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey);
		signature.update(plainData);
		return signature.verify(signatureData);
	}
	
	

}
