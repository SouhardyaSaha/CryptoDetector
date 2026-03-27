package CryptoApp;

import java.util.ArrayList;
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

public class CryptoDetector {

    public static void main(String[] args) {
        System.out.println("--- 1. Initializing Environment ---");
        List<AnalysisInputLocation> inputLocations = new ArrayList<>();
        // Point to the newly compiled CryptoApp
        inputLocations.add(new JavaClassPathAnalysisInputLocation("src/test/resources/CryptoApp/binary"));
        JavaView view = new JavaView(inputLocations);

        System.out.println("\n--- 2. Class Hierarchy Analysis ---");
        ViewTypeHierarchy typeHierarchy = new ViewTypeHierarchy(view);
        JavaClassType protocolInterface = JavaIdentifierFactory.getInstance().getClassType("MyCryptoProtocol");

        // FIXED: Using implementersOf because MyCryptoProtocol is an interface
        System.out.println("Discovered implementations of MyCryptoProtocol: "
                + typeHierarchy.implementersOf(protocolInterface));

        System.out.println("\n--- 3. Call Graph Construction ---");

        // FIXED: Define the specific entry point for our Android-like application component
        JavaClassType cryptoAppType = JavaIdentifierFactory.getInstance().getClassType("CryptoApp");
        MethodSignature entryPoint = JavaIdentifierFactory.getInstance().getMethodSignature(
                cryptoAppType,
                JavaIdentifierFactory.getInstance().getMethodSubSignature(
                        "processPayment",
                        VoidType.getInstance(), // The method returns void
                        Collections.singletonList(protocolInterface) // It takes 1 argument: MyCryptoProtocol
                )
        );

        CallGraphAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);

        // Pass the entry point directly into the initialize method
        CallGraph cg = cha.initialize(Collections.singletonList(entryPoint));

        System.out.println("Call Graph successfully built from entry point: processPayment()");

        System.out.println("\n--- 4. Hunting for Vulnerabilities ---");

        // SootUp 1.2.0 compliant way to build the Target API signature: Cipher.getInstance(String)
        ClassType cipherClassType = JavaIdentifierFactory.getInstance().getClassType("javax.crypto.Cipher");
        ClassType stringClassType = JavaIdentifierFactory.getInstance().getClassType("java.lang.String");

        MethodSignature cipherGetInstanceSig = JavaIdentifierFactory.getInstance().getMethodSignature(
                cipherClassType,
                JavaIdentifierFactory.getInstance().getMethodSubSignature(
                        "getInstance",
                        cipherClassType,
                        Collections.singletonList(stringClassType)
                )
        );

        // Query the Call Graph: Which methods in the app eventually call Cipher.getInstance?
        cg.callsTo(cipherGetInstanceSig).forEach(callerSignature -> {

            // Retrieve the actual SootMethod using the signature
            if (view.getMethod(callerSignature).isPresent()) {
                SootMethod callerMethod = view.getMethod(callerSignature).get();

                System.out.println("\n[!] Cryptographic API found inside method: "
                        + callerMethod.getDeclaringClassType().getClassName()
                        + "." + callerMethod.getName());

                // Trigger Data Flow to extract the string!
                analyzeDataFlow(callerMethod);
            }
        });

        System.out.println("\n--- Scan Complete ---");
    }

    /**
     * Extracts the Jimple Body and finds the variable passed to the API.
     */
    private static void analyzeDataFlow(SootMethod method) {
        if (!method.hasBody()) return;

        List<Stmt> stmts = method.getBody().getStmts();

        for (int i = 0; i < stmts.size(); i++) {
            Stmt stmt = stmts.get(i);
            JStaticInvokeExpr invokeExpr = getInvokeExpression(stmt);

            if (invokeExpr != null
                    && invokeExpr.getMethodSignature().getName().equals("getInstance")
                    && invokeExpr.getMethodSignature().getDeclClassType().getClassName().equals("javax.crypto.Cipher")) {

                // SootUp 1.2.0 compliant way to get the first argument
                Value argument = invokeExpr.getArgs().get(0);

                if (argument instanceof StringConstant) {
                    String algo = ((StringConstant) argument).getValue();
                    evaluateSecurity(algo, "Hardcoded String");
                } else if (argument instanceof Local) {
                    System.out.println("   -> Variable detected. Initiating Backward Trace...");
                    traceVariableBackward(argument, stmts, i);
                }
            }
        }
    }

    /**
     * Reverses up the Jimple statements to find where the Local variable was assigned.
     */
    private static void traceVariableBackward(Value targetVariable, List<Stmt> stmts, int callIndex) {
        // Walk backward from the API call
        for (int i = callIndex - 1; i >= 0; i--) {
            Stmt previousStmt = stmts.get(i);

            if (previousStmt instanceof JAssignStmt) {
                JAssignStmt assignStmt = (JAssignStmt) previousStmt;

                if (assignStmt.getLeftOp().equivTo(targetVariable)) {
                    Value rightSide = assignStmt.getRightOp();

                    if (rightSide instanceof StringConstant) {
                        String resolvedString = ((StringConstant) rightSide).getValue();
                        evaluateSecurity(resolvedString, "Resolved via Data Flow");
                        return;
                    }
                }
            }
        }
        System.out.println("   -> [FAILED] Could not resolve variable.");
    }

    /**
     * Safely extracts a static invocation from Jimple.
     */
    private static JStaticInvokeExpr getInvokeExpression(Stmt stmt) {
        if (stmt instanceof JAssignStmt && ((JAssignStmt) stmt).getRightOp() instanceof JStaticInvokeExpr) {
            return (JStaticInvokeExpr) ((JAssignStmt) stmt).getRightOp();
        } else if (stmt instanceof JInvokeStmt && ((JInvokeStmt) stmt).getInvokeExpr() instanceof JStaticInvokeExpr) {
            return (JStaticInvokeExpr) ((JInvokeStmt) stmt).getInvokeExpr();
        }
        return null;
    }

    /**
     * Security Evaluation
     */
    private static void evaluateSecurity(String algo, String detectionMethod) {
        String upper = algo.toUpperCase();
        if (upper.contains("RSA") || upper.contains("MD5") || upper.contains("SHA1") || upper.contains("DES")) {
            System.out.println("   -> [VULNERABLE] Algorithm: " + algo + " (" + detectionMethod + ")");
        } else if (upper.contains("AES") || upper.contains("CHACHA")) {
            System.out.println("   -> [SAFE] Algorithm: " + algo + " (" + detectionMethod + ")");
        }
    }
}