package symmetric;

import asymmetric.Rsa2048;
import hash.Sha256;

public class Test {
	
	public static void main(String[] args) throws Exception {
		
		Sha256 sha = new Sha256();
		Rsa2048 rsa = new Rsa2048();
		Aes256 aes = new Aes256();
		
		rsa.generateKeyPair();
		aes.generateKey();
		aes.generateIv();
		
		String text = "안녕하세요";
		System.out.println("text : " + text);
		System.out.println("해싱 : " + sha.hashing(text));
		System.out.println("=======================================================");
		System.out.println("rsa enc : " + rsa.rsaEncrypt(text));
		System.out.println("rsa dec : " + rsa.rsaDecrypt(rsa.rsaEncrypt(text)));
		System.out.println("rsa sign : " + rsa.rsaSign(text.getBytes()));
		System.out.println("rsa ver : " + rsa.rsaVerify(rsa.rsaSign(text.getBytes()), text.getBytes()));
		System.out.println("=======================================================");
		System.out.println("aes enc : " + aes.aesEncrypt(text));
		System.out.println("aes dec : " + new String(aes.aesDecrypt(aes.aesEncrypt(text))));
		
	}
}
