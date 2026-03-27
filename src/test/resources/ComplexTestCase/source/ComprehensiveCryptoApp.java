import javax.crypto.Cipher;

abstract class BaseCryptoHandler {
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

        if (isLegacyMode) {
            selectedAlgo = "DES/ECB/PKCS5Padding"; // Vulnerable
        } else {
            selectedAlgo = "AES/GCM/NoPadding";    // Safe
        }

        executeCipher(selectedAlgo);
    }
}

public class ComprehensiveCryptoApp {
    public void processCryptography() throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        EnterpriseHandler handler = new EnterpriseHandler();
        handler.process(true);
        handler.process(false);
    }
}