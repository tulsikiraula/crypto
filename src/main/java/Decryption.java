import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Tiger(AMIT) on 26-06-2018.
 */
public class Decryption {

     public static void main(String args[]) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
         String encryptedString = "W0JANzdmMDNiYjE=";
         String originalString = getOriginalString(encryptedString);

         System.out.println("original String is : " +originalString);
     }

    private static String getOriginalString(String encryptedString) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {

         byte[] key = new byte[]{'a','z','s','n','y','r','g','o','l','k','h','t','v','d','g','w'};
        SecretKeySpec secretKeySpec = new SecretKeySpec(key,"AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec iv = new IvParameterSpec(new byte[cipher.getBlockSize()]);

        cipher.init(Cipher.DECRYPT_MODE,secretKeySpec,iv);

        String  decodedString = new sun.misc.BASE64Decoder().decodeBuffer(encryptedString).toString();
        System.out.println("decoded sting :" +decodedString);

        System.out.println(cipher.update(decodedString.getBytes()).toString());
        return cipher.update(decodedString.getBytes()).toString();

    }


}
