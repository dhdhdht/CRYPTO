package cryptoki;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Cryptoki2 {

	public static void main(String[] args) throws Exception {
		boolean t = true;
		while (t) {
			Scanner sc = new Scanner(System.in);
			System.out.println("Choose number([1]:RSA, [2]:AES, [3]:Hash, [4]:Quit)");
			int number = sc.nextInt();
			switch (number) {
			// RSA
			case 1:
				System.out.println("원하는 작업을 선택하세요([1]GenerateKey [2]Encrypt [3]Decrypt [4]Sign [5]Verify)");
				int rnum = sc.nextInt();
				if (rnum == 1) {
					System.out.println("키 사이즈를 입력해주세요(1024, 2048)");
					int rSize = sc.nextInt();
					if (rSize == 1024 | rSize == 2048) {
						HashMap<String, String> keypair = generateKeyPair(rSize);
						String publicKey = keypair.get("publicKey");
						String privateKey = keypair.get("privateKey");
						System.out.println("PublicKey  : " + publicKey);
						System.out.println("\nPrivateKey : " + privateKey);
					} else {
						System.out.println("1024, 2048중에서 입력해주세요!!");
						break;
					}
				} else if (rnum == 2) {
					System.out.println("암호화할 텍스트를 입력하세요");
					String rText = sc.next();
					System.out.println("발급받은 PublicKey를 입력하세요");
					String ePubKey = sc.next();
					String rEncrypt = rsaEncrypt(rText, ePubKey);
					System.out.println("암호화 결과 : " + rEncrypt);
				} else if (rnum == 3) {
					System.out.println("발급받은 PrivateKey를 입력하세요");
					String ePriKey = sc.next();
					System.out.println("암호문을 입력하세요");
					String rEncrypt = sc.next();
					String rDecrypt = rsaDecrypt(rEncrypt, ePriKey);
					System.out.println("복호화 결과 : " + rDecrypt);
				} else if (rnum == 4) {
					System.out.println("텍스트를 입력하세요");
					String rText = sc.next();
					System.out.println("발급받은 PrivateKey를 입력하세요");
					String ePriKey = sc.next();
					String rSign = rsaSign(ePriKey, rText.getBytes());
					System.out.println("전자서명 결과 : " + rSign);
				} else if (rnum == 5) {
					System.out.println("비교할 텍스트를 입력하세요");
					String rText = sc.next();
					System.out.println("발급받은 PublicKey를 입력하세요");
					String ePubKey = sc.next();
					System.out.println("검증할 서명을 입력하세요");
					String rSign = sc.next();
					boolean rVerify = rsaVerify(ePubKey, rSign, rText.getBytes());
					System.out.println("전자서명 결과 : " + rVerify);
				} else {
					System.out.println("잘못된 번호입니다.");

				}
				break;
			// AES
			case 2:
				System.out.println("원하는 작업을 선택하세요([1]GenerateKey [2]GenerateIV [3]Encrypt [4]Decrypt)");
				int anum = sc.nextInt();
				if (anum == 1) {
					System.out.println("키 사이즈를 입력해주세요(128, 192, 256)");
					int aSize = sc.nextInt();
					if (aSize == 128 | aSize == 192 | aSize == 256) {
						String secretKey = generateKey(aSize);
						System.out.println("SecretKey  : " + secretKey);
					} else {
						System.out.println("128, 192, 256 중에서 입력해주세요!!");
						break;
					}
				} else if (anum == 2) {
					String iv = generateIv();
					System.out.println("IV : " + iv);
				} else if (anum == 3) {
					System.out.println("텍스트를 입력하세요");
					String aText = sc.next();
					System.out.println("발급받은 IV를 입력하세요");
					String eIv = sc.next();
					System.out.println("발급받은 SecretKey를 입력하세요");
					String eSecretKey = sc.next();
					String aEncrypt = aesEncrypt(aText, eIv, eSecretKey);
					System.out.println("암호화 결과 : " + aEncrypt);
				} else if (anum == 4) {
					System.out.println("암호화에 사용한 IV를 입력하세요");
					String dIv = sc.next();
					System.out.println("발급받은 SecretKey를 입력하세요");
					String dSecretKey = sc.next();
					System.out.println("암호문을 입력하세요");
					String aEncrypt = sc.next();
					String aDecrypt = aesDecrypt(aEncrypt, dIv, dSecretKey);
					System.out.println("복호화 결과 : " + aDecrypt);
				} else {
					System.out.println("잘못된 번호입니다.");
				}

				break;

			// Hash
			case 3:
				System.out.println("텍스트를 입력하세요");
				String hText = sc.next();
				System.out.println("해시값 크기를 입력해주세요(256, 512)");
				int hSize = sc.nextInt();
				if (hSize == 256 | hSize == 512) {
					String hashing = hashing(hText, hSize);
					System.out.println("해싱 결과 : " + hashing);
				} else {
					System.out.println("256, 512 중에서 입력해주세요!!");
				}
				break;
				
			case 4:
				System.out.println("프로그램 종료");
				t = false;
				break;

			default:
				System.out.println("번호 안의 숫자를 입력해주세요!");
			}

		}
	}

	// *****************************RSA*****************************
	// 키 쌍 생성
	public static HashMap<String, String> generateKeyPair(int size) {
		HashMap<String, String> stringKeypair = new HashMap<>();
		try {
			// 키의 알고리즘 RSA로 설정
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(size);
			KeyPair pair = generator.generateKeyPair();

			PublicKey publicKey = pair.getPublic();
			PrivateKey privateKey = pair.getPrivate();

			// key base64로 인코딩
			String stringPubKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
			String stringPriKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());

			stringKeypair.put("publicKey", stringPubKey);
			stringKeypair.put("privateKey", stringPriKey);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return stringKeypair;
	}

	// 암호화 (return base64)
	public static String rsaEncrypt(String plainData, String stringPubKey) {
		String encryptData = null;
		try {
			// 키 디코딩
			byte[] bytePublicKey = Base64.getDecoder().decode(stringPubKey.getBytes());
			// 키 인코딩
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

			// 평문 암호화
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] byteEncryptData = cipher.doFinal(plainData.getBytes());
			// 인코딩(Base64 인코딩)
			encryptData = Base64.getEncoder().encodeToString(byteEncryptData);

		} catch (Exception e) {
//			e.printStackTrace();
			System.out.println("PublicKey를 다시 확인해 주세요.");
		}

		return encryptData;
	}

	// 복호화 (return base64)
	public static String rsaDecrypt(String encryptData, String stringPriKey) {
		String decryptData = null;
		try {
			// 키 디코딩
			byte[] bytePrivateKey = Base64.getDecoder().decode(stringPriKey.getBytes());
			// 키 인코딩
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);
			// 암호문 복호화(Base64 -> privatekey 복호화)
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privateKey);

			byte[] byteEncryptData = Base64.getDecoder().decode(encryptData.getBytes());
			byte[] byteDecryptData = cipher.doFinal(byteEncryptData);
			decryptData = new String(byteDecryptData);
			// 인코딩(Base64 인코딩)
			// decryptData = Base64.getEncoder().encodeToString(byteDecryptData);

		} catch (Exception e) {
			System.out.println("PrivateKey 혹은 암호문이 맞지않습니다.");
		}

		return decryptData;
	}

	// 전자서명
	public static String rsaSign(String stringPriKey, byte[] plainData) {
		String result = null;
		try {
			// 키 디코딩
			byte[] bytePrivateKey = Base64.getDecoder().decode(stringPriKey.getBytes());
			// 키 인코딩
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(bytePrivateKey);
			PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

			// 전자서명 생성
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(privateKey);
			signature.update(plainData);
			byte[] signatureData = signature.sign();
			// 인코딩(Base64 인코딩)
			result = Base64.getEncoder().encodeToString(signatureData);

		} catch (Exception e) {
			System.out.println("PrivateKey를 다시 확인해 주세요.");
		}

		return result;
	}

	// 전자서명 검증
	public static boolean rsaVerify(String stringPubKey, String signData, byte[] plainData)
			throws GeneralSecurityException {
		boolean result = false;
		try {
			// 키 디코딩
			byte[] bytePublicKey = Base64.getDecoder().decode(stringPubKey.getBytes());
			// 키 인코딩
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(bytePublicKey);
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
			// 서명문 디코딩
			byte[] signatureData = Base64.getDecoder().decode(signData);
			// 전자서명 검증
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initVerify(publicKey);
			signature.update(plainData);
			result = signature.verify(signatureData);
		} catch (GeneralSecurityException e) {
			System.out.println("PublicKey 혹은 서명을 다시 확인해주세요!");
		}

		return result;
	}

	// *****************************AES*****************************
	// 비밀키 생성
	public static String generateKey(int size) throws NoSuchAlgorithmException {
		// 키 생성
		KeyGenerator generator = KeyGenerator.getInstance("AES");
		SecureRandom random = new SecureRandom();
		generator.init(size, random);
		Key secureKey = generator.generateKey();

		// 인코딩(Base64 인코딩)
		String stringSecKey = Base64.getEncoder().encodeToString(secureKey.getEncoded());
		return stringSecKey;
	}

	// 1. 초기화 벡터(IV) 생성
	public static String generateIv() {
		// 1) 내부에서 16byte로 크기고정
		byte[] ivBytes = new byte[16];
		// SecureRandom 사용
		SecureRandom random = new SecureRandom();
		random.nextBytes(ivBytes);
		// 인코딩(Base64 인코딩)
		String stringIv = Base64.getEncoder().encodeToString(ivBytes);
		return stringIv;
	}

	// 암호화
	public static String aesEncrypt(String plainData, String stringIv, String stringSecKey) {
		String encryptData = null;
		if (stringIv.length() == 24) {
			try {
				// 키, IV 디코딩
				byte[] bSecKey = Base64.getDecoder().decode(stringSecKey.getBytes());
				byte[] byteIv = Base64.getDecoder().decode(stringIv.getBytes());
				// 키, IV 인코딩
				SecretKeySpec keySpec = new SecretKeySpec(bSecKey, "AES");
				IvParameterSpec ivParamSpec = new IvParameterSpec(byteIv);

				// 평문 암호화
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivParamSpec);

				byte[] byteEncryptData = cipher.doFinal(plainData.getBytes());
				// 인코딩(Base64 인코딩)
				encryptData = Base64.getEncoder().encodeToString(byteEncryptData);
			} catch (Exception e) {
				System.out.println("SecretKey를 다시 확인해주세요.");
			}
		} else {
			System.out.println("IV 길이가 맞지않습니다.");
		}
		return encryptData;
	}

	// 복호화
	public static String aesDecrypt(String encryptData, String stringIv, String stringSecKey) {
		String decryptData = null;
		if (stringIv.length() == 24) {
			try {
				// 키, IV 디코딩
				byte[] byteKey = Base64.getDecoder().decode(stringSecKey.getBytes());
				byte[] byteIv = Base64.getDecoder().decode(stringIv.getBytes());
				// 키, IV 인코딩
				SecretKeySpec keySpec = new SecretKeySpec(byteKey, "AES");
				IvParameterSpec ivParamSpec = new IvParameterSpec(byteIv);

				// 암호문 복호화
				Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				cipher.init(Cipher.DECRYPT_MODE, keySpec, ivParamSpec);

				byte[] byteEncryptData = Base64.getDecoder().decode(encryptData);
				byte[] byteDecryptData = cipher.doFinal(byteEncryptData);
				decryptData = new String(byteDecryptData);
				// 인코딩(Base64 인코딩)
				// decryptData = Base64.getEncoder().encodeToString(byteDecryptData);

			} catch (Exception e) {
				System.out.println("SecretKey 혹은 IV를 다시 확인해주세요");
			}
		} else {
			System.out.println("IV 길이가 맞지않습니다.");
		}
		return decryptData;
	}

	// *****************************HASH*****************************
	// 해싱
	public static String hashing(String message, int size) throws NoSuchAlgorithmException {
		// 1. 메시지 입력
		MessageDigest md = MessageDigest.getInstance("SHA-" + size);
		// 2. 메시지 해싱
		md.update(message.getBytes());

		// 3. Base64 인코딩
		String result = Base64.getEncoder().encodeToString(md.digest());

		return result;
	}
}
