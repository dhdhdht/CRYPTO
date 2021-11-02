package hash;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Sha256 {

	// 해싱
	public String hashing(String message) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(message.getBytes());
		String result = Base64.getEncoder().encodeToString(md.digest());

		return result;
	}
}
