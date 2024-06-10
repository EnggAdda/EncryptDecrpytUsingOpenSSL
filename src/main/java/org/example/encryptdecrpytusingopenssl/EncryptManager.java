package org.example.encryptdecrpytusingopenssl;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EncryptManager {

    private PublicKey publicKey;

    public static final String PUBLIC_KEY_OPENSSL = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp2IlQZ0Bzdj902fQ+iwffbVA5r/NMfniu3094OQ9V9zH+GQhnLSpLC+/6U7NkT3IHVoOdxVRGm3L7+9gu5adI0c+oHYNu5XhD+0QhAWq7GcifKE/cZnHsa2uLwd9WgxmS5RWv3CpT1lARA2YiO73WGVrPZdKxCNL928V5qyMSaiPLQ6lHc+nFuRf0hTLk2HxGQS1TfXAyZdZKTbyoMsfqNvYeWbnSddKQOLy9muq8EAEAfWjusAMpJvd7TeorAmjkMqJLY/9cYINy+2Z4siP9Erp8mUU8227e7Bi+7XkZ8eSw4/E/NinY5WmKKZsNnKNTvN6mDmrtcLryGYy9AYrgwIDAQAB";

    public void initPublicKey() {

        try {
            X509EncodedKeySpec x509EncodedKeySpec =  new X509EncodedKeySpec(decode(PUBLIC_KEY_OPENSSL));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            this.publicKey = publicKey;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] decode (String data){
        return Base64.getDecoder().decode(data);
    }

    public String encode (byte [] data){
        return Base64.getEncoder().encodeToString(data);
    }

    public String encrypt(String message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] messageToByte = message.getBytes();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        byte[] encryptedBytes  = cipher.doFinal(messageToByte);
        return encode(encryptedBytes);
    }

}