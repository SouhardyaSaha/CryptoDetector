package ast;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.symbolsolver.JavaSymbolSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.CombinedTypeSolver;
import com.github.javaparser.symbolsolver.resolution.typesolvers.ReflectionTypeSolver;

import java.io.File;
import java.io.FileNotFoundException;

/**
 * Detects cryptographic API usage and classifies algorithms for PQC (Post-Quantum Cryptography) migration.
 * Orchestrates the analysis by configuring the parser and delegating to the CryptoAPIVisitor for AST traversal.
 */
public class CryptoDetector {


    static void main(String[] args) {
        String filePathArg = "src/test/resources/AST/DummyApp.java";
        analyzeCryptoUsage(filePathArg);
    }

    /**
     * Analyzes a Java file for cryptographic API usage and classifies algorithms.
     *
     * @param filePath the path to the Java file to analyze
     */
    private static void analyzeCryptoUsage(String filePath) {
        // Configure the Symbol Solver for Dataflow Analysis
        CombinedTypeSolver combinedTypeSolver = new CombinedTypeSolver();
        combinedTypeSolver.add(new ReflectionTypeSolver());
        JavaSymbolSolver symbolSolver = new JavaSymbolSolver(combinedTypeSolver);
        StaticJavaParser.getParserConfiguration().setSymbolResolver(symbolSolver);

        File fileToAnalyze = new File(filePath);

        try {
            if (!fileToAnalyze.exists()) {
                System.err.println("Error: File not found - " + fileToAnalyze.getAbsolutePath());
                return;
            }
            CompilationUnit cu = StaticJavaParser.parse(fileToAnalyze);
            System.out.println("Analyzing file: " + fileToAnalyze.getAbsolutePath());
            System.out.println("=".repeat(50));
            cu.accept(new CryptoAPIVisitor(), null);
            System.out.println("=".repeat(50));
            System.out.println("Analysis complete.");
        } catch (FileNotFoundException e) {
            System.err.println("Error: File not found - " + fileToAnalyze.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Error parsing file: " + e.getMessage());
            if (e.getCause() != null) {
                System.err.println("Caused by: " + e.getCause().getMessage());
            }
        }
    }
}