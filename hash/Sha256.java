package hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Sha256 {

	// 해싱
	public String hashing(String message) throws NoSuchAlgorithmException {
		// 1. 메시지 입력
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		// 2. 메시지 해싱
		md.update(message.getBytes());

		// 3. Base64 인코딩
		String result = Base64.getEncoder().encodeToString(md.digest());

		return result;
	}
}
