import javax.crypto.Cipher;

// CASE 5: The Complex Inter-procedural Inheritance Pattern
abstract class BaseCryptoHandler {
    // The API call is here, but the algorithm string comes from the subclass!
    protected void executeCipher(String algorithm) throws Exception {
        getCipher(algorithm);
    }

    private void getCipher(String algorithm) throws Exception
    {
        Cipher.getInstance(algorithm);
    }
}

class EnterpriseHandler extends BaseCryptoHandler {
    public void process(boolean isLegacyMode) throws Exception {
        String selectedAlgo;
        // If/Else block assigns different values to the same variable
        if (isLegacyMode) {
            selectedAlgo = "DES/ECB/PKCS5Padding"; // Vulnerable
        } else {
            selectedAlgo = "AES/GCM/NoPadding";    // Safe
        }

        // Passes the variable across method and class boundaries
        executeCipher(selectedAlgo);
    }
}

public class ComprehensiveCryptoApp {
    public void processCryptography() throws Exception {
        // Cases 1-4... (Keep your existing code here)
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        // Triggering Case 5
        EnterpriseHandler handler = new EnterpriseHandler();
        handler.process(true);
        handler.process(false);
    }
}