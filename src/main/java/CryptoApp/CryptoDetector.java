package CryptoApp;

import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
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

public class CryptoDetector {

    private static final Set<String> TARGET_CLASSES = Set.of(
            "javax.crypto.Cipher",
            "java.security.MessageDigest",
            "java.security.KeyPairGenerator",
            "javax.crypto.KeyGenerator"
    );

    private static JavaView view;
    private static CallGraph cg;

    // Prevents the scanner from analyzing the same method in an infinite loop
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
            System.err.println("Could not find ComprehensiveCryptoApp.");
            return;
        }

        CallGraphAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);
        cg = cha.initialize(Collections.singletonList(entryMethodSignature));

        SootMethod methodToAnalyze = view.getMethod(entryMethodSignature).get();
        System.out.println("==================================================");

        scanMethod(methodToAnalyze);

        System.out.println("Analysis Complete.");
    }

    private static void scanMethod(SootMethod method) {
        // Echo Fix: Stop if we have already scanned this exact method
        if (!visitedMethods.add(method.getSignature().toString())) {
            return;
        }

        if (!method.hasBody()) return;
        List<Stmt> stmts = method.getBody().getStmts();

        for (int i = 0; i < stmts.size(); i++) {
            Stmt stmt = stmts.get(i);

            if (stmt.containsInvokeExpr()) {
                AbstractInvokeExpr invokeExpr = (AbstractInvokeExpr) stmt.getInvokeExpr();

                String calledMethod = invokeExpr.getMethodSignature().getName();
                String declaringClass = invokeExpr.getMethodSignature().getDeclClassType().getClassName();

                if (calledMethod.equals("getInstance") && (
                        declaringClass.contains("Cipher") ||
                                declaringClass.contains("MessageDigest") ||
                                declaringClass.contains("KeyPairGenerator") ||
                                declaringClass.contains("KeyGenerator"))) {

                    Value argument = invokeExpr.getArgs().getFirst();

                    // Create the base path for this discovery (e.g., "[BaseCryptoHandler.executeCipher]")
                    LinkedList<String> callChain = new LinkedList<>();
                    callChain.add(getShortMethodName(method));

                    if (argument instanceof StringConstant) {
                        String algorithm = ((StringConstant) argument).getValue();
                        AlgorithmClassifier.classifyAlgorithm(declaringClass, algorithm, callChain, "Direct String Literal");
                    }
                    else if (argument instanceof Local) {
                        // Pass the chain down into the backward trace
                        traceLocalDefinition(argument, declaringClass, method, stmts, i, callChain);
                    }
                }

                // Recursive Forward Jump
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

    private static void traceLocalDefinition(Value localVariable, String apiClass, SootMethod currentMethod, List<Stmt> stmts, int startIndex, LinkedList<String> callChain) {
        for (int i = startIndex - 1; i >= 0; i--) {
            Stmt currentStmt = stmts.get(i);

            if (currentStmt instanceof JAssignStmt) {
                JAssignStmt assignStmt = (JAssignStmt) currentStmt;

                if (assignStmt.getLeftOp().equivTo(localVariable)) {
                    Value rightSide = assignStmt.getRightOp();

                    if (rightSide instanceof StringConstant) {
                        String algorithm = ((StringConstant) rightSide).getValue();
                        AlgorithmClassifier.classifyAlgorithm(apiClass, algorithm, callChain, "Resolved via Data Flow");
                    }
                }
            }

            // Cross Method Boundary Jump!
            if (currentStmt instanceof JIdentityStmt) {
                JIdentityStmt identityStmt = (JIdentityStmt) currentStmt;

                if (identityStmt.getLeftOp().equivTo(localVariable) && identityStmt.getRightOp() instanceof JParameterRef) {

                    int paramIndex = ((JParameterRef) identityStmt.getRightOp()).getIndex();

                    cg.callsTo(currentMethod.getSignature()).forEach(callerSignature -> {
                        if (view.getMethod(callerSignature).isPresent()) {
                            SootMethod callerMethod = view.getMethod(callerSignature).get();
                            traceArgumentFromCaller(callerMethod, currentMethod.getSignature(), paramIndex, apiClass, callChain);
                        }
                    });
                }
            }
        }
    }

    private static void traceArgumentFromCaller(SootMethod callerMethod, MethodSignature targetSignature, int paramIndex, String apiClass, LinkedList<String> callChain) {
        if (!callerMethod.hasBody()) return;
        List<Stmt> stmts = callerMethod.getBody().getStmts();

        // We jumped up a level! Prepend this caller to our path tracking list.
        LinkedList<String> newChain = new LinkedList<>(callChain);
        newChain.addFirst(getShortMethodName(callerMethod));

        for (int i = 0; i < stmts.size(); i++) {
            Stmt stmt = stmts.get(i);

            if (stmt.containsInvokeExpr()) {
                AbstractInvokeExpr invokeExpr = (AbstractInvokeExpr) stmt.getInvokeExpr();

                // Polymorphism Fix: Use getSubSignature to match the method regardless of inheritance
                if (invokeExpr.getMethodSignature().getSubSignature().equals(targetSignature.getSubSignature())) {

                    Value argument = invokeExpr.getArgs().get(paramIndex);

                    if (argument instanceof StringConstant) {
                        String algorithm = ((StringConstant) argument).getValue();
                        // Pass our updated path list to the classifier!
                        AlgorithmClassifier.classifyAlgorithm(apiClass, algorithm, newChain, "Inter-Procedural Trace");
                    } else if (argument instanceof Local) {
                        // Keep tracing backward inside the caller's body
                        traceLocalDefinition(argument, apiClass, callerMethod, stmts, i, newChain);
                    }
                }
            }
        }
    }

    /**
     * Helper to clean up the UI by extracting just the "ClassName.methodName"
     */
    private static String getShortMethodName(SootMethod method) {
        String fullClass = method.getDeclaringClassType().getClassName();
        String shortClass = fullClass.contains(".") ? fullClass.substring(fullClass.lastIndexOf('.') + 1) : fullClass;
        return shortClass + "." + method.getName();
    }
}