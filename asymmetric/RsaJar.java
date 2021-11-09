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

public class RsaJar {
	
	//키 쌍 생성
	public HashMap<String, String> generateKeyPair(int size) {
		HashMap<String, String> stringKeypair = new HashMap<>();
		try {
			//키의 알고리즘 RSA로 설정
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(size);
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
	public String rsaEncrypt(String plainData, String stringPubKey) {
		String encryptData = null;
		try {
			//키 디코딩
			byte[] bytePublicKey = Base64.getDecoder().decode(stringPubKey.getBytes());
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
			//키 인코딩
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
			
			//평문 암호화
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] byteEncryptData = cipher.doFinal(plainData.getBytes());
			//인코딩(Base64 인코딩)
			encryptData = Base64.getEncoder().encodeToString(byteEncryptData);
			
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return encryptData;
	}
	
	//복호화 (return base64)
	public String rsaDecrypt(String encryptData, String stringPriKey) {
		String decryptData = null;
		try {
			//키 디코딩
			byte[] bytePrivateKey = Base64.getDecoder().decode(stringPriKey.getBytes());
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
			//키 인코딩
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			//암호문 복호화(Base64 -> privatekey 복호화)
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			
			byte[] byteEncryptData = Base64.getDecoder().decode(encryptData.getBytes());
			byte[] byteDecryptData = cipher.doFinal(byteEncryptData);
			//decryptData = new String(byteDecryptData);
			//인코딩(Base64 인코딩)
			decryptData = Base64.getEncoder().encodeToString(byteDecryptData);
			
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		return decryptData;
	}
	
	//전자서명
	public String rsaSign(String stringPriKey, byte[] plainData) throws GeneralSecurityException {
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		//키 디코딩
		byte[] bytePrivateKey = Base64.getDecoder().decode(stringPriKey.getBytes());
		//키 인코딩
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
		
		//전자서명 생성
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(plainData);
		byte[] signatureData = signature.sign();
		//인코딩(Base64 인코딩)
		String result = Base64.getEncoder().encodeToString(signatureData);
		
		return result;
	}
	
	//전자서명 검증
	public boolean rsaVerify(String stringPubKey, String signData, byte[] plainData) throws GeneralSecurityException {
		//키 디코딩
		byte[] bytePublicKey = Base64.getDecoder().decode(stringPubKey.getBytes());
		X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
		//키 인코딩
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
		
		//서명문 디코딩
		byte[] signatureData = Base64.getDecoder().decode(signData);
		//전자서명 검증
		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey);
		signature.update(plainData);
		return signature.verify(signatureData);
	}
	
	

}
