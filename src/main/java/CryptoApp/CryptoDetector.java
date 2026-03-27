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

    private static final String appPath = "src/test/resources/ComplexTestCase/binary";
    private static final String className = "ComprehensiveCryptoApp";
    private static final String entryMethodName = "processCryptography";

    private static JavaView view;
    private static CallGraph cg;
    private static final Set<String> visitedMethods = new HashSet<>();

    public static void main(String[] args) {
        System.out.println("SootUp Analysis...\n");

        AnalysisInputLocation inputLocation = new JavaClassPathAnalysisInputLocation(appPath);
        view = new JavaView(Collections.singletonList(inputLocation));

        JavaIdentifierFactory idFactory = JavaIdentifierFactory.getInstance();
        JavaClassType appType = idFactory.getClassType(className);

        MethodSignature entrySignature = idFactory.getMethodSignature(
                appType,
                idFactory.getMethodSubSignature(entryMethodName, VoidType.getInstance(), Collections.emptyList())
        );

        if (view.getMethod(entrySignature).isEmpty()) {
            System.err.println("Could not find ComprehensiveCryptoApp.");
            return;
        }

        CallGraphAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);
        cg = cha.initialize(Collections.singletonList(entrySignature));

        System.out.println("==================================================");
        scanMethod(view.getMethod(entrySignature).get());
        System.out.println("Analysis Complete.");
    }

    private static void scanMethod(SootMethod method) {
        if (!visitedMethods.add(method.getSignature().toString()) || !method.hasBody()) {
            return;
        }

        List<Stmt> stmts = method.getBody().getStmts();

        // 1. Analyze local statements
        for (int i = 0; i < stmts.size(); i++) {
            Stmt stmt = stmts.get(i);
            if (!stmt.containsInvokeExpr()) {
                continue;
            }

            AbstractInvokeExpr invokeExpr = (AbstractInvokeExpr) stmt.getInvokeExpr();
            String calledMethod = invokeExpr.getMethodSignature().getName();
            String declaringClass = invokeExpr.getMethodSignature().getDeclClassType().getClassName();

            if ("getInstance".equals(calledMethod) && isTargetApi(declaringClass)) {
                Value argument = invokeExpr.getArgs().getFirst();

                LinkedList<String> callChain = new LinkedList<>();
                callChain.add(getShortMethodName(method));

                if (argument instanceof StringConstant) {
                    String algorithm = ((StringConstant) argument).getValue();
                    AlgorithmClassifier.classifyAlgorithm(declaringClass, algorithm, callChain, "Direct String Literal");
                } else if (argument instanceof Local) {
                    traceLocalDefinition(argument, declaringClass, method, stmts, i, callChain);
                }
            }
        }

        // 2. Traverse forward call graph edges for custom methods
        cg.callsFrom(method.getSignature()).forEach(targetSignature -> {
            String targetClass = targetSignature.getDeclClassType().getClassName();
            if (!isJavaLibrary(targetClass)) {
                view.getMethod(targetSignature).ifPresent(CryptoDetector::scanMethod);
            }
        });
    }

    private static void traceLocalDefinition(Value localVariable, String apiClass, SootMethod currentMethod, List<Stmt> stmts, int startIndex, LinkedList<String> callChain) {
        for (int i = startIndex - 1; i >= 0; i--) {
            Stmt stmt = stmts.get(i);

            // Handle standard assignments
            if (stmt instanceof JAssignStmt) {
                JAssignStmt assignStmt = (JAssignStmt) stmt;
                if (assignStmt.getLeftOp().equivTo(localVariable) && assignStmt.getRightOp() instanceof StringConstant) {
                    String algorithm = ((StringConstant) assignStmt.getRightOp()).getValue();
                    AlgorithmClassifier.classifyAlgorithm(apiClass, algorithm, callChain, "Resolved via Data Flow");
                }
            }

            // Handle inter-procedural parameters
            if (stmt instanceof JIdentityStmt) {
                JIdentityStmt identityStmt = (JIdentityStmt) stmt;
                if (identityStmt.getLeftOp().equivTo(localVariable) && identityStmt.getRightOp() instanceof JParameterRef) {
                    int paramIndex = ((JParameterRef) identityStmt.getRightOp()).getIndex();

                    cg.callsTo(currentMethod.getSignature()).forEach(callerSignature -> {
                        view.getMethod(callerSignature).ifPresent(callerMethod ->
                                traceArgumentFromCaller(callerMethod, currentMethod.getSignature(), paramIndex, apiClass, callChain)
                        );
                    });
                }
            }
        }
    }

    private static void traceArgumentFromCaller(SootMethod callerMethod, MethodSignature targetSignature, int paramIndex, String apiClass, LinkedList<String> callChain) {
        if (!callerMethod.hasBody()) return;

        LinkedList<String> newChain = new LinkedList<>(callChain);
        newChain.addFirst(getShortMethodName(callerMethod));

        List<Stmt> stmts = callerMethod.getBody().getStmts();

        for (int i = 0; i < stmts.size(); i++) {
            Stmt stmt = stmts.get(i);
            if (!stmt.containsInvokeExpr()) {
                continue;
            }

            AbstractInvokeExpr invokeExpr = (AbstractInvokeExpr) stmt.getInvokeExpr();

            if (invokeExpr.getMethodSignature().getSubSignature().equals(targetSignature.getSubSignature())) {
                Value argument = invokeExpr.getArgs().get(paramIndex);

                if (argument instanceof StringConstant) {
                    String algorithm = ((StringConstant) argument).getValue();
                    AlgorithmClassifier.classifyAlgorithm(apiClass, algorithm, newChain, "Inter-Procedural Trace");
                } else if (argument instanceof Local) {
                    traceLocalDefinition(argument, apiClass, callerMethod, stmts, i, newChain);
                }
            }
        }
    }

    // --- Helper Methods ---

    private static boolean isTargetApi(String className) {
        // 1. Strict Full Package Match (Best practice for Enterprise)
        if (TARGET_CLASSES.contains(className)) {
            return true;
        }

        // 2. Exact Equality Fallback for Phantom Classes
        // Using .equals() instead of .contains() prevents false positives like "MyCustomCipher"
        return className.equals("Cipher") ||
                className.equals("MessageDigest") ||
                className.equals("KeyPairGenerator") ||
                className.equals("KeyGenerator");
    }

    private static boolean isJavaLibrary(String className) {
        return className.startsWith("java.") || className.startsWith("javax.") || className.startsWith("sun.");
    }

    private static String getShortMethodName(SootMethod method) {
        String fullClass = method.getDeclaringClassType().getClassName();
        int lastDotIndex = fullClass.lastIndexOf('.');
        String shortClass = lastDotIndex != -1 ? fullClass.substring(lastDotIndex + 1) : fullClass;
        return shortClass + "." + method.getName();
    }
}