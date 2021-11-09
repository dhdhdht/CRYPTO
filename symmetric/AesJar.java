package symmetric;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesJar {

	// 비밀키 생성
	public String generateKey(int size) throws NoSuchAlgorithmException {
		//키 생성
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		SecureRandom random = new SecureRandom();
		generator.init(size, random);
		Key secureKey = generator.generateKey();

		//인코딩(Base64 인코딩)
		String stringSecKey = Base64.getEncoder().encodeToString(secureKey.getEncoded());
		
		return stringSecKey;
	}

	// 1. 초기화 벡터(IV) 생성
	public String generateIv() {
		// 1) 내부에서 16byte로 크기고정
		byte[] ivBytes = new byte[16];
		// SecureRandom 사용
		SecureRandom random = new SecureRandom();
		random.nextBytes(ivBytes);
		//인코딩(Base64 인코딩)
		String stringIv = Base64.getEncoder().encodeToString(ivBytes);
		
		return stringIv;
	}

	// 암호화
	public String aesEncrypt(String plainData, String stringIv, String stringSecKey) {
		String encryptData = null;

		try {
			//키, IV 디코딩
			byte[] bSecKey = Base64.getDecoder().decode(stringSecKey.getBytes());
			byte[] byteIv = Base64.getDecoder().decode(stringIv.getBytes());
			//키, IV 인코딩
			SecretKeySpec keySpec = new SecretKeySpec(bSecKey, "AES");
			IvParameterSpec ivParamSpec = new IvParameterSpec(byteIv);

			//평문 암호화
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParamSpec);

			byte[] byteEncryptData = cipher.doFinal(plainData.getBytes());
			//인코딩(Base64 인코딩)
			encryptData = Base64.getEncoder().encodeToString(byteEncryptData);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return encryptData;
	}

	// 복호화
	public String aesDecrypt(String encryptData, String stringIv, String stringSecKey) {
		String decryptData = null;
		try {
			//키, IV 디코딩
			byte[] byteKey = Base64.getDecoder().decode(stringSecKey.getBytes());
			byte[] byteIv = Base64.getDecoder().decode(stringIv.getBytes());
			//키, IV 인코딩
			SecretKeySpec keySpec = new SecretKeySpec(byteKey, "AES");
			IvParameterSpec ivParamSpec = new IvParameterSpec(byteIv);
			
			//암호문 복호화
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec);

			byte[] byteEncryptData = Base64.getDecoder().decode(encryptData);
			byte[] byteDecryptData = cipher.doFinal(byteEncryptData);
			//decryptData = new String(byteDecryptData);
			//인코딩(Base64 인코딩)
			decryptData = Base64.getEncoder().encodeToString(byteDecryptData);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return decryptData;
	}

}