package CryptoApp;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class AlgorithmClassifier {

    private static final Set<String> VULNERABLE_ALGORITHMS = Set.of(
            "RSA", "MD5", "SHA-1", "DSA", "ECC", "EC"
    );

    private static final List<CryptoFinding> findings = new ArrayList<>();

    public static void classifyAlgorithm(String apiClass, String algorithm, List<String> callChain, String detectionMethod) {
        boolean vulnerable = isVulnerable(algorithm);

        findings.add(new CryptoFinding(algorithm, apiClass, callChain, detectionMethod, vulnerable));

        System.out.printf("[+] Detected %s in %s\n", algorithm, callChain.getFirst());
    }

    private static boolean isVulnerable(String algorithm) {
        String normalized = algorithm.toUpperCase();
        return VULNERABLE_ALGORITHMS.stream().anyMatch(normalized::contains);
    }

    public static void writeJsonReport(String filePath) {
        StringBuilder json = new StringBuilder("[\n");

        for (int i = 0; i < findings.size(); i++) {
            CryptoFinding f = findings.get(i);

            String flowArray = f.callChain().stream()
                    .map(step -> "\"" + step + "\"")
                    .collect(Collectors.joining(", ", "[", "]"));

            json.append("  {\n")
                    .append("    \"algorithm\": \"").append(f.algorithm()).append("\",\n")
                    .append("    \"api_class\": \"").append(f.apiClass()).append("\",\n")
                    .append("    \"vulnerable\": ").append(f.isVulnerable()).append(",\n")
                    .append("    \"detection_method\": \"").append(f.detectionMethod()).append("\",\n")
                    .append("    \"flow\": ").append(flowArray).append("\n")
                    .append("  }");

            if (i < findings.size() - 1) json.append(",");
            json.append("\n");
        }
        json.append("]");

        try (FileWriter writer = new FileWriter(filePath)) {
            writer.write(json.toString());
            System.out.println("\nAudit report saved to: " + filePath);
        } catch (IOException e) {
            System.err.println("Failed to write report: " + e.getMessage());
        }
    }
}