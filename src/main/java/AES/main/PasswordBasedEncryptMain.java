package AES.main;

import AES.util.AESUtil;
import org.bouncycastle.jcajce.provider.symmetric.AES;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class PasswordBasedEncryptMain {

    public static void main(String[] args) {

     try {
         String plainText = "ercankarakaya";
         String password = "ercan";
         String salt = "123456";
         IvParameterSpec ivParameterSpec = AESUtil.generateIV();
         SecretKey secretKey = AESUtil.getKeyFromPassword(password,salt);
         String cipherText = AESUtil.encryptPasswordBased(plainText,secretKey,ivParameterSpec);
         String decryptedCipherText = AESUtil.decryptPasswordBased(cipherText,secretKey,ivParameterSpec);

         System.out.println("CipherText : "+cipherText);
         System.out.println("DecryptedCipherText : "+decryptedCipherText);
     }catch (Exception ex){
         ex.printStackTrace();
     }

    }
}
