package asymmetric;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
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

import javax.crypto.Cipher;

public class Rsa2048 {
	
//	//@Test
	public static void main(String[] args) throws GeneralSecurityException {
		generateKeyPair();
		
		String text = "안녕하세요";
		System.out.println("평문 : " + text);
		
		String encrypt = rsaEncrypt(text);
		System.out.println("암호화 : " + encrypt);
		
		String decrypt = rsaDecrypt(encrypt);
		System.out.println("복호화(base64) : " + decrypt);
		
		System.out.println("서명 데이터 :  " + text);
		String signature = rsaSign(text.getBytes());
		System.out.println("서명문 : " + signature);
		boolean verified = rsaVerify(signature, text.getBytes());
		System.out.println("검증결과 : " + verified);
	}
	
	
	//키 쌍 생성 (파일에 저장)
	public static void generateKeyPair() throws GeneralSecurityException {
		File file = new File("alias.pub");
		File file2 = new File("alias.pri");
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(2048);
		KeyPair pair = generator.generateKeyPair();
		
		PublicKey publicKey = pair.getPublic();
		PrivateKey privateKey = pair.getPrivate();
		
		//key base64로 인코딩
		String stringPubKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		String stringPriKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
		
		//key file에 저장
		try {
			BufferedWriter bw1 = new BufferedWriter(new FileWriter(file));
			bw1.write(stringPubKey);
			bw1.newLine();
			bw1.close();
			BufferedWriter bw2 = new BufferedWriter(new FileWriter(file2));
			bw2.write(stringPriKey);
			bw2.newLine();
			bw2.close();
		} catch(Exception e) {
			e.printStackTrace();
		}	
	}
	
	//암호화 (return base64)
	public static String rsaEncrypt(String plainData) {
		String encryptData = null;
		String stringPubKey = null;
		BufferedReader brPubKey = null;
		
		try {
			//file에 있는 publickey 불러오기
			brPubKey = new BufferedReader(new FileReader("alias.pub"));
			stringPubKey = brPubKey.readLine();
			
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
	public static String rsaDecrypt(String encryptData) {
		String decryptData = null;
		String stringPriKey = null;
		BufferedReader brPriKey = null;
		
		try {
			//file에 있는 privatekey 불러오기
			brPriKey = new BufferedReader(new FileReader("alias.pri"));
			stringPriKey = brPriKey.readLine();
			
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			byte[] bytePrivateKey = Base64.getDecoder().decode(stringPriKey.getBytes());
			
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			
			byte[] byteEncryptData = Base64.getDecoder().decode(encryptData.getBytes());
			byte[] byteDecryptData = cipher.doFinal(byteEncryptData);
			decryptData = Base64.getEncoder().encodeToString(byteDecryptData);
			
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return decryptData;
	}
	
	//전자서명
	public static String rsaSign(byte[] plainData) throws GeneralSecurityException {
		String result = null;
		String stringPriKey = null;
		BufferedReader brPriKey = null;
		try {
			brPriKey = new BufferedReader(new FileReader("alias.pri"));
			stringPriKey = brPriKey.readLine();
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			//인코딩된 개인키 개인키객체로 변환
			byte[] bytePrivateKey = Base64.getDecoder().decode(stringPriKey.getBytes());
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(privateKey);
			signature.update(plainData);
			byte[] signatureData = signature.sign();
			result = Base64.getEncoder().encodeToString(signatureData);
			
		}catch(Exception e) {
			e.printStackTrace();
		}
		
		
		return result;
	}
	
	//전자서명 검증
	public static boolean rsaVerify(String signData, byte[] plainData) throws GeneralSecurityException {
		PublicKey publicKey;
		String stringPubKey = null;
		BufferedReader brPubKey = null;
		boolean result = false;
		try {
			brPubKey = new BufferedReader(new FileReader("alias.pub"));
			stringPubKey = brPubKey.readLine();
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			
			//인코딩된 공개키 공개키객체로 변환
			byte[] bytePublicKey = Base64.getDecoder().decode(stringPubKey.getBytes());
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
			publicKey = keyFactory.generatePublic(publicKeySpec);
			
			//인코딩된 signData 디코딩
			byte[] signatureData = Base64.getDecoder().decode(signData);
			
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initVerify(publicKey);
			signature.update(plainData);
			result = signature.verify(signatureData);
			
		} catch(Exception e) {
			e.printStackTrace();
		} 
		
		return result;
	}
	
	

}
