package ast;

import java.util.Set;

/**
 * Classifies cryptographic algorithms as vulnerable or safe for quantum computing.
 * Determines whether algorithms need migration to post-quantum cryptography alternatives.
 */
public class AlgorithmClassifier {

    private static final Set<String> VULNERABLE_ALGORITHMS = Set.of(
            "RSA", "MD5", "SHA-1", "DSA", "ECC", "EC"
    );

    /**
     * Classifies an algorithm as vulnerable or safe.
     * Prints the classification result.
     *
     * @param apiClass the cryptographic API class name (e.g., "Cipher", "MessageDigest")
     * @param algorithm the algorithm string to classify (e.g., "RSA", "AES")
     * @param lineNum the line number where the algorithm is used
     */
    public static void classifyAlgorithm(String apiClass, String algorithm, int lineNum) {
        String upperAlgo = algorithm.toUpperCase();
        boolean isVulnerable = VULNERABLE_ALGORITHMS.stream()
                .anyMatch(upperAlgo::contains);

        System.out.println("Line " + lineNum + ":");
        System.out.println("  API Class:  " + apiClass);
        System.out.println("  Algorithm:  " + algorithm);
        System.out.println("  Status:     " + (isVulnerable ? "⚠️  VULNERABLE (PQC Migration Required)" : "✓ SAFE/STANDARD"));
    }

    /**
     * Checks if an algorithm is vulnerable.
     *
     * @param algorithm the algorithm string to check
     * @return true if the algorithm is in the vulnerable set, false otherwise
     */
    public static boolean isVulnerable(String algorithm) {
        String upperAlgo = algorithm.toUpperCase();
        return VULNERABLE_ALGORITHMS.stream()
                .anyMatch(upperAlgo::contains);
    }
}

