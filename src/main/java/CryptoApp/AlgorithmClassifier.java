package CryptoApp;

import java.util.Set;

public class AlgorithmClassifier {

    private static final Set<String> VULNERABLE_ALGORITHMS = Set.of(
            "RSA", "MD5", "SHA-1", "DSA", "ECC", "EC"
    );

    // CHANGED: Swapped 'int lineNum' for 'String methodName'
    public static void classifyAlgorithm(String apiClass, String algorithm, String methodName, String detectionMethod) {
        String upperAlgo = algorithm.toUpperCase();
        boolean isVulnerable = VULNERABLE_ALGORITHMS.stream()
                .anyMatch(upperAlgo::contains);

        String shortApiClass = apiClass.substring(apiClass.lastIndexOf('.') + 1);

        // CHANGED: Output now points developers to the specific method instead of a line number
        System.out.println("Detection in method [" + methodName + "] via " + detectionMethod + ":");
        System.out.println("  API Class:  " + shortApiClass);
        System.out.println("  Algorithm:  " + algorithm);
        System.out.println("  Status:     " + (isVulnerable ? "⚠️ VULNERABLE (PQC Migration Required)" : "✓ SAFE/STANDARD"));
        System.out.println();
    }
}