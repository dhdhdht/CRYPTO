package test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Aes256 {
	
	private final SecureRandom secureRandom = new SecureRandom();
    private final static int GCM_IV_LENGTH = 12;

    //@Test
    public void testEncryption() throws Exception {
        //create new random key
        byte[] key = new byte[16];
        secureRandom.nextBytes(key);
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        byte[] associatedData = "ProtocolVersion1".getBytes(StandardCharsets.UTF_8); //meta data you want to verify with the secret message

        String message = "the secret message";

        byte[] cipherText = encrypt(message, secretKey, associatedData);
        String decrypted = decrypt(cipherText, secretKey, associatedData);

        assertEquals(message, decrypted);
        
    }
    
    //암호화 코드 작성
    private byte[] encrypt(String plaintext, SecretKey secretKey, byte[] associatedData) throws Exception {

        byte[] iv = new byte[GCM_IV_LENGTH]; //NEVER REUSE THIS IV WITH SAME KEY
        secureRandom.nextBytes(iv);
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv); //128 bit auth tag length
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        if (associatedData != null) {
            cipher.updateAAD(associatedData);
        }

        byte[] cipherText = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        ByteBuffer byteBuffer = ByteBuffer.allocate(iv.length + cipherText.length);
        byteBuffer.put(iv);
        byteBuffer.put(cipherText);
        return byteBuffer.array();
    }

   // 복호화 코드 작성
    private String decrypt(byte[] cipherMessage, SecretKey secretKey, byte[] associatedData) throws Exception {
        final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        //use first 12 bytes for iv
        AlgorithmParameterSpec gcmIv = new GCMParameterSpec(128, cipherMessage, 0, GCM_IV_LENGTH);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmIv);

        if (associatedData != null) {
            cipher.updateAAD(associatedData);
        }
        //use everything from 12 bytes on as ciphertext
        byte[] plainText = cipher.doFinal(cipherMessage, GCM_IV_LENGTH, cipherMessage.length - GCM_IV_LENGTH);

        return new String(plainText, StandardCharsets.UTF_8);
    }

}
