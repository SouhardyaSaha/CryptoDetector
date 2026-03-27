package CryptoApp;

import java.util.Collections;
import java.util.List;
import sootup.callgraph.CallGraph;
import sootup.callgraph.CallGraphAlgorithm;
import sootup.callgraph.ClassHierarchyAnalysisAlgorithm;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.JStaticInvokeExpr;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JInvokeStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.core.typehierarchy.ViewTypeHierarchy;
import sootup.core.types.ClassType;
import sootup.core.types.VoidType;
import sootup.java.bytecode.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.JavaIdentifierFactory;
import sootup.java.core.types.JavaClassType;
import sootup.java.core.views.JavaView;

/** * This example illustrates how to combine Class Hierarchy Analysis (CHA),
 * Call Graph construction, and intra-procedural Backward Data Flow Analysis
 * to detect vulnerable cryptographic API parameters.
 */
public class CryptoDetector {

    public static void main(String[] args) {

        // Create an AnalysisInputLocation, which points to a directory.
        // All class files will be loaded from the directory.
        AnalysisInputLocation inputLocation =
                new JavaClassPathAnalysisInputLocation("src/test/resources/CryptoApp/binary");

        // Create a view for the project, which allows us to retrieve classes
        JavaView view = new JavaView(Collections.singletonList(inputLocation));

        // Create type hierarchy
        final ViewTypeHierarchy typeHierarchy = new ViewTypeHierarchy(view);

        // Specify class types we want to receive information about
        JavaClassType protocolInterface = JavaIdentifierFactory.getInstance().getClassType("MyCryptoProtocol");
        System.out.println("Implementers of MyCryptoProtocol: " + typeHierarchy.implementersOf(protocolInterface));

        // Create a signature for the class and entry method we want to analyze
        JavaClassType cryptoAppType = JavaIdentifierFactory.getInstance().getClassType("CryptoApp");
        MethodSignature entryMethodSignature =
                JavaIdentifierFactory.getInstance()
                        .getMethodSignature(
                                cryptoAppType,
                                JavaIdentifierFactory.getInstance()
                                        .getMethodSubSignature(
                                                "processPayment",
                                                VoidType.getInstance(),
                                                Collections.singletonList(protocolInterface)));

        // Create CG by initializing CHA with entry method(s)
        CallGraphAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);
        CallGraph cg = cha.initialize(Collections.singletonList(entryMethodSignature));

        // Create a signature for the target API we want to track
        ClassType cipherClassType = JavaIdentifierFactory.getInstance().getClassType("javax.crypto.Cipher");
        ClassType stringClassType = JavaIdentifierFactory.getInstance().getClassType("java.lang.String");

        MethodSignature targetApiSignature = JavaIdentifierFactory.getInstance().getMethodSignature(
                cipherClassType,
                JavaIdentifierFactory.getInstance().getMethodSubSignature(
                        "getInstance",
                        cipherClassType,
                        Collections.singletonList(stringClassType)
                )
        );

        // Traverse the Call Graph to find callers of the target API
        cg.callsTo(targetApiSignature).forEach(callerSignature -> {

            // Check if the method is present in the view before retrieving
            if (!view.getMethod(callerSignature).isPresent()) {
                return;
            }

            SootMethod method = view.getMethod(callerSignature).get();
            System.out.println("\nAnalyzing method: " + method.getSignature());

            // Perform Data Flow Analysis on the resolved method
            analyzeDataFlow(method);
        });
    }

    /**
     * Scans the Jimple body for the target API and extracts its parameters.
     */
    private static void analyzeDataFlow(SootMethod method) {
        if (!method.hasBody()) {
            return;
        }

        List<Stmt> stmts = method.getBody().getStmts();

        for (int i = 0; i < stmts.size(); i++) {
            Stmt stmt = stmts.get(i);
            JStaticInvokeExpr invokeExpr = extractStaticInvocation(stmt);

            // Check if the statement contains our target Cipher.getInstance call
            if (invokeExpr != null
                    && invokeExpr.getMethodSignature().getName().equals("getInstance")
                    && invokeExpr.getMethodSignature().getDeclClassType().getClassName().equals("javax.crypto.Cipher")) {

                Value argument = invokeExpr.getArgs().get(0);

                if (argument instanceof StringConstant) {
                    String algorithm = ((StringConstant) argument).getValue();
                    System.out.println(" -> Hardcoded Constant Detected: " + algorithm);
                    evaluateSecurity(algorithm);
                } else if (argument instanceof Local) {
                    System.out.println(" -> Local Variable Detected (" + argument + "). Tracing definition...");
                    traceLocalDefinition(argument, stmts, i);
                }
            }
        }
    }

    /**
     * Performs an intra-procedural backward trace to find the definition of a Local variable.
     */
    private static void traceLocalDefinition(Value localVariable, List<Stmt> stmts, int startIndex) {
        for (int i = startIndex - 1; i >= 0; i--) {
            Stmt currentStmt = stmts.get(i);

            if (currentStmt instanceof JAssignStmt) {
                JAssignStmt assignStmt = (JAssignStmt) currentStmt;

                // If the left side matches our local variable, we found the definition
                if (assignStmt.getLeftOp().equivTo(localVariable)) {
                    Value rightSide = assignStmt.getRightOp();

                    if (rightSide instanceof StringConstant) {
                        String algorithm = ((StringConstant) rightSide).getValue();
                        System.out.println(" -> Variable Resolved To: " + algorithm);
                        evaluateSecurity(algorithm);
                        return;
                    }
                }
            }
        }
        System.out.println(" -> Could not resolve variable definition.");
    }

    /**
     * Extracts a JStaticInvokeExpr from a given statement, if present.
     */
    private static JStaticInvokeExpr extractStaticInvocation(Stmt stmt) {
        if (stmt instanceof JAssignStmt && ((JAssignStmt) stmt).getRightOp() instanceof JStaticInvokeExpr) {
            return (JStaticInvokeExpr) ((JAssignStmt) stmt).getRightOp();
        } else if (stmt instanceof JInvokeStmt && ((JInvokeStmt) stmt).getInvokeExpr() instanceof JStaticInvokeExpr) {
            return (JStaticInvokeExpr) ((JInvokeStmt) stmt).getInvokeExpr();
        }
        return null;
    }

    /**
     * Evaluates the security posture of the extracted cryptographic algorithm.
     */
    private static void evaluateSecurity(String algorithm) {
        String normalizedAlgo = algorithm.toUpperCase();
        if (normalizedAlgo.contains("RSA") || normalizedAlgo.contains("MD5") || normalizedAlgo.contains("DES")) {
            System.out.println("    [VULNERABILITY] Weak/Quantum-Vulnerable Algorithm found.");
        } else if (normalizedAlgo.contains("AES") || normalizedAlgo.contains("CHACHA")) {
            System.out.println("    [SAFE] Modern standard algorithm found.");
        }
    }
}