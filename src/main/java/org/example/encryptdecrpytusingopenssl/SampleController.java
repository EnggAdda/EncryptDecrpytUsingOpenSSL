package org.example.encryptdecrpytusingopenssl;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@RestController
public class SampleController {

    @GetMapping("/get")
    public String get(){
        String str = "Youtube";
       EncryptManager encryptManager = new EncryptManager();
       encryptManager.initPublicKey();
       DecryptManager decryptManager  = new DecryptManager();
       decryptManager.initPrivateKey();

        try {
           String encryptedString = encryptManager.encrypt(str);
            System.out.println("encrypted message :-"+encryptedString);
            String decryptedString = decryptManager.decrypt(encryptedString);
            System.out.println("decrypted message :-  "+decryptedString);

        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }

        return str;
    }
}
