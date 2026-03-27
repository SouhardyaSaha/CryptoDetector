import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

public class ComprehensiveCryptoApp {

    public void processCryptography() throws Exception {
        // CASE 1: Direct String Literals
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");

        // CASE 2: Simple Local Variables
        String weakHash = "MD5";
        MessageDigest md5Digest = MessageDigest.getInstance(weakHash);

        String strongCipher = "AES/GCM/NoPadding";
        Cipher aesCipher = Cipher.getInstance(strongCipher);

        // CASE 3: Multiple Variables on a Single Line
        String legacyHash = "SHA-1", futureProofAlgo = "SHA3-256";
        MessageDigest sha1Digest = MessageDigest.getInstance(legacyHash);
        MessageDigest sha3Digest = MessageDigest.getInstance(futureProofAlgo);

        // CASE 4: Different API Target Classes
        String keyPairAlgo = "EC";
        KeyPairGenerator ecKeyPairGen = KeyPairGenerator.getInstance(keyPairAlgo);
        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");

        String dsaAlgorithm = "DSA";
        KeyPairGenerator dsaKeyPairGen = KeyPairGenerator.getInstance(dsaAlgorithm);
    }
}