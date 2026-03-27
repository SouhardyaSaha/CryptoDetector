package CryptoApp;

import java.util.Collections;
import java.util.List;
import java.util.Set;

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
import sootup.core.types.VoidType;
import sootup.java.bytecode.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.JavaIdentifierFactory;
import sootup.java.core.types.JavaClassType;
import sootup.java.core.views.JavaView;

/**
 * Detects cryptographic API usage across multiple target classes and classifies
 * algorithms using backward data flow analysis on the Jimple IR.
 */
public class CryptoDetector {

    // Define the APIs we care about tracking
    private static final Set<String> TARGET_CLASSES = Set.of(
            "javax.crypto.Cipher",
            "java.security.MessageDigest",
            "java.security.KeyPairGenerator",
            "javax.crypto.KeyGenerator"
    );

    public static void main(String[] args) {

        System.out.println("Initializing SootUp Analysis...\n");
        AnalysisInputLocation inputLocation =
                new JavaClassPathAnalysisInputLocation("src/test/resources/ComprehensiveCryptoApp/binary");

        JavaView view = new JavaView(Collections.singletonList(inputLocation));

        // 1. Setup the Entry Point (ComprehensiveCryptoApp.processCryptography)
        JavaClassType appType = JavaIdentifierFactory.getInstance().getClassType("ComprehensiveCryptoApp");
        MethodSignature entryMethodSignature = JavaIdentifierFactory.getInstance().getMethodSignature(
                appType,
                JavaIdentifierFactory.getInstance().getMethodSubSignature(
                        "processCryptography", VoidType.getInstance(), Collections.emptyList()));

        // Check if the target app compiled correctly
        if (view.getMethod(entryMethodSignature).isEmpty()) {
            System.err.println("Could not find ComprehensiveCryptoApp. Did you compile it?");
            return;
        }

        // 2. Build the Call Graph starting from processCryptography
        CallGraphAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);
        CallGraph cg = cha.initialize(Collections.singletonList(entryMethodSignature));

        // 3. Since we want to analyze the entry method itself, we pass it to the Data Flow analyzer
        SootMethod methodToAnalyze = view.getMethod(entryMethodSignature).get();
        System.out.println("Scanning Method: " + methodToAnalyze.getSignature() + "\n");
        System.out.println("==================================================");

        analyzeDataFlow(methodToAnalyze);

        System.out.println("==================================================");
        System.out.println("Analysis Complete.");
    }

    /**
     * Scans the Jimple body for target APIs and extracts their parameters.
     */
    /**
     * Scans the Jimple body for target APIs and extracts their parameters.
     */
    private static void analyzeDataFlow(SootMethod method) {
        if (!method.hasBody()) {
            System.out.println("   [!] Error: Method has no body.");
            return;
        }

        List<Stmt> stmts = method.getBody().getStmts();
        System.out.println(" -> Extracting " + stmts.size() + " Jimple statements...\n");

        for (int i = 0; i < stmts.size(); i++) {
            Stmt stmt = stmts.get(i);
            JStaticInvokeExpr invokeExpr = extractStaticInvocation(stmt);

            if (invokeExpr != null) {
                String calledMethod = invokeExpr.getMethodSignature().getName();
                String declaringClass = invokeExpr.getMethodSignature().getDeclClassType().getClassName();

                // X-RAY DEBUG: Print every static method call the analyzer sees
                System.out.println("   [DEBUG] Found Static Call: " + declaringClass + "." + calledMethod);

                if (calledMethod.equals("getInstance")) {

                    // FIXED: Made the matching more flexible in case SootUp drops the "javax.crypto." prefix
                    if (declaringClass.contains("Cipher") ||
                            declaringClass.contains("MessageDigest") ||
                            declaringClass.contains("KeyPairGenerator") ||
                            declaringClass.contains("KeyGenerator")) {

                        Value argument = invokeExpr.getArgs().getFirst();

                        // Case A: Direct String Literal
                        if (argument instanceof StringConstant) {
                            String algorithm = ((StringConstant) argument).getValue();
                            AlgorithmClassifier.classifyAlgorithm(declaringClass, algorithm, method.getName(), "Direct String Literal");
                        }
                        // Case B: Local Variable
                        else if (argument instanceof Local) {
                            traceLocalDefinition(argument, declaringClass, method.getName(), stmts, i);
                        }
                    }
                }
            }
        }
    }

    /**
     * Walks backward through the control flow to find where a variable was assigned.
     */
    private static void traceLocalDefinition(Value localVariable, String apiClass, String methodName, List<Stmt> stmts, int startIndex) {
        for (int i = startIndex - 1; i >= 0; i--) {
            Stmt currentStmt = stmts.get(i);

            if (currentStmt instanceof JAssignStmt) {
                JAssignStmt assignStmt = (JAssignStmt) currentStmt;

                // If the left side of the assignment matches our target variable
                if (assignStmt.getLeftOp().equivTo(localVariable)) {
                    Value rightSide = assignStmt.getRightOp();

                    if (rightSide instanceof StringConstant) {
                        String algorithm = ((StringConstant) rightSide).getValue();
                        AlgorithmClassifier.classifyAlgorithm(apiClass, algorithm, methodName, "Resolved via Data Flow");
                        return;
                    }
                }
            }
        }
        System.out.println("Method [" + methodName + "]: Could not resolve variable definition for " + apiClass + "\n");
    }

    /**
     * Safely extracts a static invocation from a Jimple statement.
     */
    private static JStaticInvokeExpr extractStaticInvocation(Stmt stmt) {
        if (stmt instanceof JAssignStmt && ((JAssignStmt) stmt).getRightOp() instanceof JStaticInvokeExpr) {
            return (JStaticInvokeExpr) ((JAssignStmt) stmt).getRightOp();
        } else if (stmt instanceof JInvokeStmt && ((JInvokeStmt) stmt).getInvokeExpr() instanceof JStaticInvokeExpr) {
            return (JStaticInvokeExpr) ((JInvokeStmt) stmt).getInvokeExpr();
        }
        return null;
    }
}