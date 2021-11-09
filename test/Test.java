package test;

import java.util.HashMap;

import asymmetric.RsaJar;
import hash.ShaJar;
import symmetric.AesJar;

public class Test {
	
	public static void main(String[] args) throws Exception {
		RsaJar rj = new RsaJar();
		AesJar aj = new AesJar();
		ShaJar sj = new ShaJar();
		String text = "안녕";
		String text1 = "하이";
		
		HashMap<String, String> keypair = rj.generateKeyPair(2048);
		String publicKey = keypair.get("publicKey");
		String privateKey = keypair.get("privateKey");
		String rencrypt = rj.rsaEncrypt(text, publicKey);
		String rdecrypt = rj.rsaDecrypt(rencrypt, privateKey);
		String signature = rj.rsaSign(privateKey, text.getBytes());
		boolean verified = rj.rsaVerify(publicKey, signature, text1.getBytes());
		
		String secretKey = aj.generateKey(256);
		String iv = aj.generateIv();
		String aencrypt = aj.aesEncrypt(text, iv, secretKey);
		String adecrypt = aj.aesDecrypt(aencrypt, iv, secretKey);
		
		System.out.println("text : " + text);
		System.out.println("해싱 : " + sj.hashing(text));
		System.out.println("=======================================================");
		System.out.println("rsa enc : " + rencrypt);
		System.out.println("rsa dec : " + rdecrypt);
		System.out.println("rsa sign : " + signature);
		System.out.println("rsa ver : " + verified);
		System.out.println("=======================================================");
		System.out.println("aes enc : " + aencrypt);
		System.out.println("aes dec : " + adecrypt);
		
	}

}
