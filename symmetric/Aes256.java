package symmetric;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Aes256 {

	// 비밀키 생성 (파일에 저장)
	public void generateKey() throws GeneralSecurityException, IOException {
		File file = new File("aeskey.jks");

		// 1. 파라미터 검증 (키의 크기 설정)
		// 2. 키 생성(SecureRandom) - 예외처리는 GeneralSecurityException에 포함
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		SecureRandom random = new SecureRandom();
		generator.init(256, random);
		Key secureKey = generator.generateKey();

		// Base64로 인코딩
		String stringSecKey = Base64.getEncoder().encodeToString(secureKey.getEncoded());
		// 3) key값 file에 저장
		BufferedWriter bw = new BufferedWriter(new FileWriter(file));
		bw.write(stringSecKey);
		bw.close();

	}

	// 1. 초기화 벡터(IV) 생성
	public void generateIv() throws Exception {
		File file = new File("aesiv.jks");

		// 1) 내부에서 16byte로 크기고정
		byte[] ivBytes = new byte[16];
		// SecureRandom 사용
		SecureRandom random = new SecureRandom();
		random.nextBytes(ivBytes);
		// Base64로 인코딩
		String stringIv = Base64.getEncoder().encodeToString(ivBytes);
		// 2) IV값 file에 저장
		BufferedWriter bw = new BufferedWriter(new FileWriter(file));
		bw.write(stringIv);
		bw.close();
	}

	// 암호화
	public String aesEncrypt(String plainData) {
		BufferedReader brSecKey = null;
		BufferedReader brIv = null;
		String stringSecKey = null;
		String encryptData = null;
		String stringIv = null;

		try {
			// file에 있는 secretkey, iv 불러오기
			brSecKey = new BufferedReader(new FileReader("aeskey.jks"));
			stringSecKey = brSecKey.readLine();
			brIv = new BufferedReader(new FileReader("aesiv.jks"));
			stringIv = brIv.readLine();

			// 1. 파라미터 검증(비밀키 검증 - Base64로 디코딩)
			byte[] bSecKey = Base64.getDecoder().decode(stringSecKey.getBytes());
			// System.out.println("bKey : " + bSecKey);
			SecretKeySpec keySpec = new SecretKeySpec(bSecKey, "AES");
			byte[] byteIv = Base64.getDecoder().decode(stringIv.getBytes());
			IvParameterSpec ivParamSpec = new IvParameterSpec(byteIv);
			// System.out.println(ivParamSpec);

			// 2. Cipher 객체 초기화 (instance 설정 및 ENCRYPT_MODE)
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParamSpec);

			// 3. 메시지 암호화 (문자열 바이트코드로 인코딩)
			byte[] byteEncryptData = cipher.doFinal(plainData.getBytes());
			// 4. 인코딩(Base64 인코딩)
			encryptData = Base64.getEncoder().encodeToString(byteEncryptData);
		} catch (Exception e) {
			// 1-1) 키 값의 Size가 다를 경우, 에러처리 - InvalidKeyException 포함
			e.printStackTrace();
		}

		return encryptData;
	}

	// 복호화
	public byte[] aesDecrypt(String encryptData) {
		String stringIv = null;
		String stringSecKey = null;
		BufferedReader brSecKey = null;
		BufferedReader brIv = null;
		byte[] decryptData = null;

		try {
			// file에 있는 key, iv값 가져오기
			brIv = new BufferedReader(new FileReader("aesiv.jks"));
			stringIv = brIv.readLine();
			brSecKey = new BufferedReader(new FileReader("aeskey.jks"));
			stringSecKey = brSecKey.readLine();

			// 1. 파라미터 검증(비밀키, IV값검증 - Base64로 디코딩)
			byte[] byteKey = Base64.getDecoder().decode(stringSecKey.getBytes());
			byte[] byteIv = Base64.getDecoder().decode(stringIv.getBytes());

			SecretKeySpec keySpec = new SecretKeySpec(byteKey, "AES");
			IvParameterSpec ivParamSpec = new IvParameterSpec(byteIv);
			// 2. Cipher 객체 초기화 (instance 설정 및 DECRYPT_MODE)
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec);

			// 3. 암호문 복호화 (Base64 디코딩)
			byte[] byteDecryptData = Base64.getDecoder().decode(encryptData);
			decryptData = cipher.doFinal(byteDecryptData);

		} catch (Exception e) {
			// 1-1) 키 값의 Size가 다를 경우, 에러처리 - InvalidKeyException 포함
			// 3-1) 복호화 실패시, 에러처리
			e.printStackTrace();
		}

		return decryptData;
	}

}