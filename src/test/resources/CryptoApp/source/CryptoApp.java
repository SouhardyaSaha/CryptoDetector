import javax.crypto.Cipher;

// 1. The Interface
interface MyCryptoProtocol {
    void encryptData() throws Exception;
}

// 2. Safe Implementation (Hardcoded String)
class SecureCrypto implements MyCryptoProtocol {
    @Override
    public void encryptData() throws Exception {
        Cipher.getInstance("AES/GCM/NoPadding");
    }
}

// 3. Vulnerable Implementation (Hidden Variable)
class LegacyCrypto implements MyCryptoProtocol {
    @Override
    public void encryptData() throws Exception {
        String badAlgo = "RSA/ECB/PKCS1Padding";
        Cipher.getInstance(badAlgo);
    }
}

// 4. The Main Application Engine
public class CryptoApp {
    public void processPayment(MyCryptoProtocol protocol) throws Exception {
        protocol.encryptData();
    }
}