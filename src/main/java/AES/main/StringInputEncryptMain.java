package AES.main;

import AES.util.AESUtil;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class StringInputEncryptMain {

    public static void main(String[] args) {

        try {
            String input = "ercankarakaya";
            SecretKey secretKey = AESUtil.generateKey(128);
            IvParameterSpec ivParameterSpec = AESUtil.generateIV();
            String algorithm = "AES/CBC/PKCS5Padding";
            String cipherText = AESUtil.encrypt(algorithm,input,secretKey,ivParameterSpec);
            String plainText = AESUtil.decrypt(algorithm,cipherText,secretKey,ivParameterSpec);

            System.out.println("CipherText : "+cipherText);
            System.out.println("PlainText : "+plainText);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

    }
}
