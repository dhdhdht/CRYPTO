package symmetric;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Aes256 {
	
	static char[] pw = "password".toCharArray();
	
//	@test
	public static void main(String[] args) throws GeneralSecurityException, Exception {
		generateKey();
		System.out.print(generateIv());
		
	}
		
	//비밀키 생성 (파일에 저장)
	public static void generateKey() throws GeneralSecurityException, IOException {
		File file = new File("aeskey.jks");
		KeyStore keyStore = KeyStore.getInstance("JKS");
		
		if(file.exists()) {
			FileInputStream fis = new FileInputStream(file);
			KeyGenerator generator = KeyGenerator.getInstance("AES");
			SecureRandom random = new SecureRandom();
			generator.init(256, random);
			Key secureKey = generator.generateKey();
			
			String stringSecKey = Base64.getEncoder().encodeToString(secureKey.getEncoded());
			BufferedWriter bw = new BufferedWriter(new FileWriter(file));
			bw.write(stringSecKey);
			bw.close();
			keyStore.load(fis, pw);
			
		} else {
			System.out.println("파일생성 실패");
		}
	}
	
	public static String generateIv() {
		byte[] ivBytes = new byte[16];
		String stringIv = Base64.getEncoder().encodeToString(ivBytes);
		return stringIv;
	}
	
//	public String aesEncrypt(String plainData) throws NoSuchAlgorithmException, NoSuchPaddingException {
//		generateIv();
//		//key 호출
//		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//		SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "AES");
//		
//		cipher.init(Cipher.ENCRYPT_MODE, key, generateIv());
//		
//		return "";
//	}
	
	public String aesDecrypt(String plainData) {
		
		return "";
	}
	
	

}
