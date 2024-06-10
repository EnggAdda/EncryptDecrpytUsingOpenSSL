package org.example.encryptdecrpytusingopenssl;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class DecryptManager {

    private PrivateKey privateKey;

    public static final String PRIVATE_KEY_OPENSSL = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCnYiVBnQHN2P3TZ9D6LB99tUDmv80x+eK7fT3g5D1X3Mf4ZCGctKksL7/pTs2RPcgdWg53FVEabcvv72C7lp0jRz6gdg27leEP7RCEBarsZyJ8oT9xmcexra4vB31aDGZLlFa/cKlPWUBEDZiI7vdYZWs9l0rEI0v3bxXmrIxJqI8tDqUdz6cW5F/SFMuTYfEZBLVN9cDJl1kpNvKgyx+o29h5ZudJ10pA4vL2a6rwQAQB9aO6wAykm93tN6isCaOQyoktj/1xgg3L7ZniyI/0SunyZRTzbbt7sGL7teRnx5LDj8T82KdjlaYopmw2co1O83qYOau1wuvIZjL0BiuDAgMBAAECggEATVrqy+VzMX5AZASdDBj7Hr329g0bGCcbdTl+sOHaRbJHilBARmspqb2RjBG6qA5s3r/BYqBr4HJwpvyycE89ZNHmrAKS+yfboOAW22TBJsrNIdrldqsyojcZgiuMb2K+ndw6sPOwk3a0YB8GaPZDQktwocC7MWT8lSf176q7lMg8OPpYyBst6lvA68dnUSoz0Mf6qwSyhYbB+3z+m4ySUJtTQG4UQPt1zHVILyxVnsEU7IzaMpd7tjsk0lgzxPwlDX4EuUkzPyFeakPPR55g4IcixFiZJSVyFQsEd9Y1pPKwljA2ditD5sM9Doep73TkQ8KNvx04pOPnuUW0NEikLQKBgQDqoJAcmY5FPEtn0sqqfNtcNBptzD5BM69wmeA4nz75do7A8qkqt6OpbWr78Kexgj5tSdlc+3fM8ZQcXZH53dY2sdopx+qrHjOE2m7TvB+vQZGl0ShQ5OVQ8ia67I2mxe1q8TkNOs1aOglDi96TjHzfP43d9oJSmk7O58nOsF5bTwKBgQC2oXoCUtW+71RllwKp+iasVSjdc3rfqmIvHAUDSqeF8n00KjcEfuYihxwMgScKqLbisjIaN3BlE/Vo7QQDnVWebhDfz43covb9UXG15/86DpZ3I8qGMkGB80efXxbiUO5SkOxyA7rCMFaxe6vGxPDk30rBJx6f+7tGuBqNJffPjQKBgDnCyXeg/fthepbWt/n8vuwWD6OUModOuBQaba7C1XgIjeBGXQsdJndhboMTndT/YWr6UT6o0bdsia/qATPoPwI8Cp9ajhUOXFSKidoqaAp3M+oEcc5oa2PgGVTPQ5gZBffb5tWw8jkSLJGqb2MXpO448S4Br9eyEVCyk2YE2VXVAoGAM8mmZ3JF2lbTf9tKjhi5TrT3WZSdiz8tiF5RrZVF293fUyOFZmj1qWTWt1UIVSVyduZA/t4pqP/330EWmk/LL5nWfyDEAYTUtRCbRhH7deMdF7u2ekdV/BuYe8DjJFn+ursN0WbtVpOOgdWn6D2AceY/tHX7YTJo8KzUGqJhmyECgYEA4GN2U9zwwc4i5ITtf8QX33UKhJLLQEX52qeEsrBP6eKY2W1l7ZabMFdmW5g08jOnPu3dsxWh6p7tY4EjvSRVozSmH6Jh2IMf2jb9aJhA6mKnZo+MJyK2X1KqFDGgEaEFTA2sKu5HIVIfixBV21fUgbq9JiwLw0AheXcbGCrths0=" ;

    public void initPrivateKey() {

        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec =  new PKCS8EncodedKeySpec(decode(PRIVATE_KEY_OPENSSL));

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            this.privateKey = privateKey;
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

    public String decrypt(String message) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessage  = cipher.doFinal(Base64.getMimeDecoder().decode(message));
        return new String(decryptedMessage);
    }
}
