package CryptoApp;

import java.util.List;
import java.util.Set;

public class AlgorithmClassifier {

    private static final Set<String> VULNERABLE_ALGORITHMS = Set.of(
            "RSA", "MD5", "SHA-1", "DSA", "ECC", "EC"
    );

    public static void classifyAlgorithm(String apiClass, String algorithm, List<String> callChain, String detectionMethod) {
        String shortApiClass = shortenClassName(apiClass);
        String path = String.join(" -> ", callChain);

        System.out.println("Flow: [" + path + "]");
        System.out.println("  Found via:   " + detectionMethod);
        System.out.println("  API used:    " + shortApiClass);
        System.out.println("  Algorithm:   " + algorithm);
        System.out.println("  Security:    " + (isVulnerableAlgorithm(algorithm) ? "PQC vulnerable" : "safe"));
        System.out.println("--------------------------------------------------");
    }

    private static boolean isVulnerableAlgorithm(String algorithm) {
        String normalized = algorithm.toUpperCase();
        return VULNERABLE_ALGORITHMS.stream().anyMatch(normalized::contains);
    }

    private static String shortenClassName(String className) {
        int lastDot = className.lastIndexOf('.');
        return className.substring(lastDot + 1);
    }
}