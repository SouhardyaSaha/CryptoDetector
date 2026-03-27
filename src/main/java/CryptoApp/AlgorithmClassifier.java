package CryptoApp;

import java.util.List;
import java.util.Set;

/**
 * Classifies cryptographic algorithms and prints their exact data flow paths.
 */
public class AlgorithmClassifier {

    private static final Set<String> VULNERABLE_ALGORITHMS = Set.of(
            "RSA", "MD5", "SHA-1", "DSA", "ECC", "EC"
    );

    public static void classifyAlgorithm(String apiClass, String algorithm, List<String> callChain, String detectionMethod) {
        String upperAlgo = algorithm.toUpperCase();
        boolean isVulnerable = VULNERABLE_ALGORITHMS.stream().anyMatch(upperAlgo::contains);

        String shortApiClass = apiClass.substring(apiClass.lastIndexOf('.') + 1);

        // Join the LinkedList together with arrows!
        String path = String.join(" -> ", callChain);

        System.out.println("Data Flow Path: [" + path + "]");
        System.out.println("  Detection:  " + detectionMethod);
        System.out.println("  API Class:  " + shortApiClass);
        System.out.println("  Algorithm:  " + algorithm);
        System.out.println("  Status:     " + (isVulnerable ? "⚠️ VULNERABLE (PQC Migration Required)" : "✓ SAFE/STANDARD"));
        System.out.println("--------------------------------------------------");
    }
}