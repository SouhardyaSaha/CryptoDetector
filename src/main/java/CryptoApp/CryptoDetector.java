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
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JIdentityStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.VoidType;
import sootup.java.bytecode.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.JavaIdentifierFactory;
import sootup.java.core.types.JavaClassType;
import sootup.java.core.views.JavaView;

import java.util.HashSet;

/**
 * Detects cryptographic API usage across multiple target classes and classifies
 * algorithms using inter-procedural backward data flow analysis on the Jimple IR.
 */
public class CryptoDetector {

    private static final Set<String> TARGET_CLASSES = Set.of(
            "javax.crypto.Cipher",
            "java.security.MessageDigest",
            "java.security.KeyPairGenerator",
            "javax.crypto.KeyGenerator"
    );

    private static JavaView view;
    private static CallGraph cg;

    private static Set<String> visitedMethods = new HashSet<>();

    public static void main(String[] args) {

        System.out.println("Initializing Inter-Procedural SootUp Analysis...\n");
        AnalysisInputLocation inputLocation =
                new JavaClassPathAnalysisInputLocation("src/test/resources/ComplexTestCase/binary");

        view = new JavaView(Collections.singletonList(inputLocation));

        JavaClassType appType = JavaIdentifierFactory.getInstance().getClassType("ComprehensiveCryptoApp");
        MethodSignature entryMethodSignature = JavaIdentifierFactory.getInstance().getMethodSignature(
                appType,
                JavaIdentifierFactory.getInstance().getMethodSubSignature(
                        "processCryptography", VoidType.getInstance(), Collections.emptyList()));

        if (view.getMethod(entryMethodSignature).isEmpty()) {
            System.err.println("Could not find ComprehensiveCryptoApp. Did you compile it?");
            return;
        }

        CallGraphAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);
        cg = cha.initialize(Collections.singletonList(entryMethodSignature));

        SootMethod methodToAnalyze = view.getMethod(entryMethodSignature).get();
        System.out.println("==================================================");

        scanMethod(methodToAnalyze);

        System.out.println("==================================================");
        System.out.println("Analysis Complete.");
    }

    private static void scanMethod(SootMethod method) {
        if (!method.hasBody()) {
            return;
        }

        if (!visitedMethods.add(method.getSignature().toString())) {
            return;
        }

        List<Stmt> stmts = method.getBody().getStmts();

        for (int i = 0; i < stmts.size(); i++) {
            Stmt stmt = stmts.get(i);

            // CLEAN NATIVE SOOTUP APPROACH: Check if the statement contains any invocation
            if (stmt.containsInvokeExpr()) {

                // Safely extract the invocation using the native base class
                AbstractInvokeExpr invokeExpr = (AbstractInvokeExpr) stmt.getInvokeExpr();

                String calledMethod = invokeExpr.getMethodSignature().getName();
                String declaringClass = invokeExpr.getMethodSignature().getDeclClassType().getClassName();

                // 1. Check if the call is one of our target cryptographic APIs
                if (calledMethod.equals("getInstance") && (
                        declaringClass.contains("Cipher") ||
                                declaringClass.contains("MessageDigest") ||
                                declaringClass.contains("KeyPairGenerator") ||
                                declaringClass.contains("KeyGenerator"))) {

                    Value argument = invokeExpr.getArgs().getFirst();

                    if (argument instanceof StringConstant) {
                        String algorithm = ((StringConstant) argument).getValue();
                        AlgorithmClassifier.classifyAlgorithm(declaringClass, algorithm, method.getName(), "Direct String Literal");
                    }
                    else if (argument instanceof Local) {
                        traceLocalDefinition(argument, declaringClass, method, stmts, i);
                    }
                }

                // 2. INTER-PROCEDURAL JUMP: If this is a call to a custom project method, recursively jump into it!
                if (!declaringClass.startsWith("java.") && !declaringClass.startsWith("javax.") && !declaringClass.startsWith("sun.")) {
                    cg.callsFrom(method.getSignature()).forEach(targetSignature -> {
                        if (view.getMethod(targetSignature).isPresent()) {
                            scanMethod(view.getMethod(targetSignature).get());
                        }
                    });
                }
            }
        }
    }

    private static void traceLocalDefinition(Value localVariable, String apiClass, SootMethod currentMethod, List<Stmt> stmts, int startIndex) {
        for (int i = startIndex - 1; i >= 0; i--) {
            Stmt currentStmt = stmts.get(i);

            if (currentStmt instanceof JAssignStmt) {
                JAssignStmt assignStmt = (JAssignStmt) currentStmt;

                if (assignStmt.getLeftOp().equivTo(localVariable)) {
                    Value rightSide = assignStmt.getRightOp();

                    if (rightSide instanceof StringConstant) {
                        String algorithm = ((StringConstant) rightSide).getValue();
                        AlgorithmClassifier.classifyAlgorithm(apiClass, algorithm, currentMethod.getName(), "Resolved via Data Flow");
                    }
                }
            }

            // Identity Assignment (e.g., algo = @parameter0) -> CROSS METHOD BOUNDARY
            if (currentStmt instanceof JIdentityStmt) {
                JIdentityStmt identityStmt = (JIdentityStmt) currentStmt;

                if (identityStmt.getLeftOp().equivTo(localVariable) && identityStmt.getRightOp() instanceof JParameterRef) {

                    int paramIndex = ((JParameterRef) identityStmt.getRightOp()).getIndex();
                    System.out.println("   [⤾] Parameter pass detected in [" + currentMethod.getName() + "]. Tracing backward to callers...");

                    cg.callsTo(currentMethod.getSignature()).forEach(callerSignature -> {
                        if (view.getMethod(callerSignature).isPresent()) {
                            SootMethod callerMethod = view.getMethod(callerSignature).get();
                            traceArgumentFromCaller(callerMethod, currentMethod.getSignature(), paramIndex, apiClass);
                        }
                    });
                }
            }
        }
    }

    private static void traceArgumentFromCaller(SootMethod callerMethod, MethodSignature targetSignature, int paramIndex, String apiClass) {
        if (!callerMethod.hasBody()) return;
        List<Stmt> stmts = callerMethod.getBody().getStmts();

        for (int i = 0; i < stmts.size(); i++) {
            Stmt stmt = stmts.get(i);

            if (stmt.containsInvokeExpr()) {
                AbstractInvokeExpr invokeExpr = (AbstractInvokeExpr) stmt.getInvokeExpr();

                // FIXED: Use getSubSignature() to ignore the class name!
                // This perfectly matches "executeCipher(String)" whether it was called on BaseHandler or EnterpriseHandler.
                if (invokeExpr.getMethodSignature().getSubSignature().equals(targetSignature.getSubSignature())) {

                    Value argument = invokeExpr.getArgs().get(paramIndex);

                    if (argument instanceof StringConstant) {
                        String algorithm = ((StringConstant) argument).getValue();
                        AlgorithmClassifier.classifyAlgorithm(apiClass, algorithm, callerMethod.getName(), "Inter-Procedural Trace");
                    } else if (argument instanceof Local) {
                        // Resume the backward trace in the CALLER'S body
                        traceLocalDefinition(argument, apiClass, callerMethod, stmts, i);
                    }
                }
            }
        }
    }
}