package AES.main;

import AES.util.AESUtil;
import org.apache.commons.io.FileUtils;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;

public class FileEncryptMain {

    public static void main(String[] args) {

     try {
         SecretKey secretKey = AESUtil.generateKey(128);
         String algorithm = "AES/CBC/PKCS5Padding";
         IvParameterSpec ivParameterSpec = AESUtil.generateIV();
         File inputFile = new File("files/example.txt");
         File encryptedFile = new File("document.encrypted");
         File decryptedFile = new File("document.decrypted");
         AESUtil.encryptFile(algorithm,secretKey,ivParameterSpec,inputFile,encryptedFile);
         AESUtil.decryptFile(algorithm,secretKey,ivParameterSpec,encryptedFile,decryptedFile);

         System.out.println(FileUtils.contentEquals(inputFile,decryptedFile));
         System.out.println("finished...");
     }catch (Exception ex){
         ex.printStackTrace();
     }

    }
}
