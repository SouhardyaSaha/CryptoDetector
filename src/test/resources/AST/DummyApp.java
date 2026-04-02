package AST;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;

/**
 * Test application demonstrating various cryptographic API usage patterns.
 * This class is used to test the CryptoDetector's ability to identify
 * vulnerable cryptographic algorithms that need PQC migration.
 */
@SuppressWarnings("unused")
public class DummyApp {

    /**
     * Exercises various cryptographic APIs with test cases for detection.
     * Each test case demonstrates a different pattern that the analyzer tracks.
     *
     * @throws Exception if any cryptographic operation fails
     */
    void processCryptography() throws Exception {

        // CASE 1: Direct String Literals ---
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // VULNERABLE - RSA
        MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256"); // SAFE - SHA-256

        // --- TEST CASE 2: Simple Local Variables ---
        // The detector uses dataflow analysis to trace the variable back to its initialization
        String weakHash = "MD5";
        MessageDigest md5Digest = MessageDigest.getInstance(weakHash); // VULNERABLE - MD5

        String strongCipher = "AES/GCM/NoPadding";
        Cipher aesCipher = Cipher.getInstance(strongCipher); // SAFE - AES

        // --- TEST CASE 3: Multiple Variables on a Single Line ---
        // Tests the detector's ability to handle complex variable declarations
        String legacyHash = "SHA-1", futureProofAlgo = "SHA3-256";
        MessageDigest sha1Digest = MessageDigest.getInstance(legacyHash); // VULNERABLE - SHA-1
        MessageDigest sha3Digest = MessageDigest.getInstance(futureProofAlgo); // SAFE - SHA3-256

        // --- TEST CASE 4: Different API Target Classes ---
        // Elliptic Curve (ECC/EC) is vulnerable to Shor's algorithm
        String keyPairAlgo = "EC";
        KeyPairGenerator ecKeyPairGen = KeyPairGenerator.getInstance(keyPairAlgo); // VULNERABLE - EC

        KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES"); // SAFE - AES

        // --- TEST CASE 5: Simplified Field-Level Test ---
        // Field-level analysis requires extended analysis (for future improvement)
        String dsaAlgorithm = "DSA";
        KeyPairGenerator dsaKeyPairGen = KeyPairGenerator.getInstance(dsaAlgorithm); // VULNERABLE - DSA

        // Dummy operations to prevent compiler optimization warnings
        rsaCipher.init(Cipher.ENCRYPT_MODE, (Key) null);
        sha256Digest.update("test".getBytes());
        md5Digest.update("test".getBytes());
        aesCipher.init(Cipher.ENCRYPT_MODE, (Key) null);
        sha1Digest.update("test".getBytes());
        sha3Digest.update("test".getBytes());
        ecKeyPairGen.generateKeyPair();
        aesKeyGen.generateKey();
        dsaKeyPairGen.generateKeyPair();
    }
}