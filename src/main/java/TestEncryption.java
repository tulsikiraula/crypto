import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Tiger(AMIT) on 24-06-2018.
 */
public class TestEncryption {

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        String originalString = "Password";
        String encryptedString = getEncryptedPassword(originalString);
        System.out.println("encrypted String is :" + encryptedString );
    }
    static String getEncryptedPassword(final String originalString) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        // byte array key
        byte[] key = new byte[]{'a','z','s','n','y','r','g','o','l','k','h','t','v','d','g','w'};

        // another method is to get bytes from string
        byte[] key1 = "kiraulatulsi1234".getBytes();

        SecretKeySpec secretKey = new SecretKeySpec(key,"AES");

        //IVparameters
        IvParameterSpec ivParameterSpec = new IvParameterSpec(new byte[16]);

        //get cipher instance, AES as algo, CBC as encryption mode and Padding is added in CBC
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        IvParameterSpec ivParameterSpec1 = new IvParameterSpec(new byte[cipher.getBlockSize()]);

        //initialize cipher
        cipher.init(Cipher.ENCRYPT_MODE,secretKey,ivParameterSpec1);

        //encrypt with dofinal as heres a single block.if multiple blocks are there use update to encrypt each block
        // and then use doFinal to the last block to add adding if any

        String encryptedString = cipher.doFinal(originalString.getBytes()).toString();

        //encode the encrypted string for more security

        String encodedString = new sun.misc.BASE64Encoder().encode(encryptedString.getBytes());

        return encodedString;
    }
}


