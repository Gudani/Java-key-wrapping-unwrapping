import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class App {
        /**
     * @param args the command line arguments
     * @throws java.security.NoSuchAlgorithmException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws java.security.spec.InvalidKeySpecException
     */
    public static void main(String[] args) throws Exception {
           // TODO code application logic here
           final String Algo = "RSA/ECB/PKCS1Padding";

           KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
           keyPairGen.initialize(2048);   //Initializing the KeyPairGenerator
           KeyPair pair = keyPairGen.generateKeyPair(); //Generating the pair of keys
           //Getting the private and public key from the key pair
           PrivateKey privKey = pair.getPrivate();   
           PublicKey publicKey = pair.getPublic(); 
        
           SecretKey aeskey = getKeyFromKeyGenerator("AES", 256);
           byte [] wrapedkey = encodeKeyForTransmission(publicKey, aeskey, Algo);
           SecretKey unwraped = decodeTransmittedKey(wrapedkey, privKey, Algo);
          
        
           System.out.println("Original key: "+ Base64.getEncoder().encodeToString(aeskey.getEncoded()));
           System.out.println("Wrapped key :" + Arrays.toString(wrapedkey));
           System.out.println("Unwrapped key: " + Base64.getEncoder().encodeToString(unwraped.getEncoded()));
          
      }
      private static SecretKey getKeyFromKeyGenerator(String cipher, int keySize) throws NoSuchAlgorithmException {
            KeyGenerator keyGenerator = KeyGenerator.getInstance(cipher);
            keyGenerator.init(keySize);
           return  keyGenerator.generateKey();
    }
    public static byte[] encodeKeyForTransmission( PublicKey encodingKey, SecretKey keyToEncode, String Algorithm ) throws NoSuchAlgorithmException,NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance( Algorithm);
        cipher.init( Cipher.WRAP_MODE, encodingKey );
        byte[] encodedKey = cipher.wrap( keyToEncode );
        
        return encodedKey;
      }
      public static SecretKey decodeTransmittedKey( byte[] transmittedKey, PrivateKey privateKey ,String Algorithm) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
    
        Cipher keyCipher = Cipher.getInstance( Algorithm );
        keyCipher.init( Cipher.UNWRAP_MODE, privateKey );
        
        return (SecretKey) keyCipher.unwrap( transmittedKey, "AES", Cipher.SECRET_KEY);
      }
}
