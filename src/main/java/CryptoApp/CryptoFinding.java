package CryptoApp;

import java.util.List;

public record CryptoFinding(String algorithm, String apiClass, List<String> callChain, String detectionMethod,
                            boolean isVulnerable) {
}