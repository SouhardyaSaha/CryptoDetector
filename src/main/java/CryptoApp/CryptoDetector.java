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

//    private static final String APP_PATH = "src/test/resources/ComprehensiveCryptoApp/binary";
    private static final String APP_PATH = "src/test/resources/ComplexTestCase/binary";
    private static final String CLASS_NAME = "ComprehensiveCryptoApp";
    private static final String ENTRY_METHOD_NAME = "processCryptography";

    private static JavaView view;
    private static CallGraph callGraph;
    private static final Set<String> visitedMethods = new HashSet<>();

    public static void main(String[] args) {
        System.out.println("SootUp Analysis...\n");

        AnalysisInputLocation inputLocation = new JavaClassPathAnalysisInputLocation(APP_PATH);
        view = new JavaView(Collections.singletonList(inputLocation));

        JavaIdentifierFactory idFactory = JavaIdentifierFactory.getInstance();
        JavaClassType appType = idFactory.getClassType(CLASS_NAME);

        MethodSignature entrySignature = idFactory.getMethodSignature(
                appType,
                idFactory.getMethodSubSignature(ENTRY_METHOD_NAME, VoidType.getInstance(), Collections.emptyList())
        );

        if (view.getMethod(entrySignature).isEmpty()) {
            System.err.println("Could not find ComprehensiveCryptoApp.");
            return;
        }

        CallGraphAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);
        callGraph = cha.initialize(Collections.singletonList(entrySignature));

        scanMethod(view.getMethod(entrySignature).get());

        System.out.println("Analysis Complete.");

        AlgorithmClassifier.writeJsonReport("reports/crypto_audit_report_1.json");
    }

    private static void scanMethod(SootMethod method) {
        if (!visitedMethods.add(method.getSignature().toString()) || !method.hasBody()) {
            return;
        }

        List<Stmt> statements = method.getBody().getStmts();

        for (int i = 0; i < statements.size(); i++) {
            Stmt stmt = statements.get(i);
            if (!stmt.containsInvokeExpr()) {
                continue;
            }

            AbstractInvokeExpr invokeExpr = (AbstractInvokeExpr) stmt.getInvokeExpr();
            String targetClassName = invokeExpr.getMethodSignature().getDeclClassType().toString();

            if (isTargetGetInstanceCall(invokeExpr, targetClassName)) {
                LinkedList<String> callChain = new LinkedList<>();
                callChain.add(getShortMethodName(method));
                Value argument = invokeExpr.getArgs().getFirst();
                traceAlgorithmArgument(argument, targetClassName, method, statements, i, callChain, "Direct String Literal");
            }
        }

        callGraph.callsFrom(method.getSignature()).forEach(targetSignature -> {
            String targetClass = targetSignature.getDeclClassType().getClassName();
            if (!isJavaLibrary(targetClass)) {
                view.getMethod(targetSignature).ifPresent(CryptoDetector::scanMethod);
            }
        });
    }

    private static void traceLocalDefinition(Value localVariable, String apiClass, SootMethod currentMethod, List<Stmt> statements, int startIndex, LinkedList<String> callChain) {
        for (int i = startIndex - 1; i >= 0; i--) {
            Stmt stmt = statements.get(i);

            if (stmt instanceof JAssignStmt) {
                JAssignStmt assignStmt = (JAssignStmt) stmt;

                if (assignStmt.getLeftOp().equivTo(localVariable)) {
                    traceAlgorithmArgument(assignStmt.getRightOp(), apiClass, currentMethod, statements, i, callChain, "Resolved via Data Flow");
                }
            }

            if (stmt instanceof JIdentityStmt) {
                JIdentityStmt identityStmt = (JIdentityStmt) stmt;
                if (identityStmt.getLeftOp().equivTo(localVariable) && identityStmt.getRightOp() instanceof JParameterRef) {
                    int paramIndex = ((JParameterRef) identityStmt.getRightOp()).getIndex();

                    callGraph.callsTo(currentMethod.getSignature()).forEach(callerSignature -> {
                        view.getMethod(callerSignature).ifPresent(callerMethod ->
                                traceArgumentFromCaller(callerMethod, currentMethod.getSignature(), paramIndex, apiClass, callChain)
                        );
                    });
                }
            }
        }
    }

    private static void traceArgumentFromCaller(SootMethod callerMethod, MethodSignature targetSignature, int paramIndex, String apiClass, LinkedList<String> callChain) {
        if (!callerMethod.hasBody()) {
            return;
        }

        LinkedList<String> newChain = new LinkedList<>(callChain);
        newChain.addFirst(getShortMethodName(callerMethod));

        List<Stmt> statements = callerMethod.getBody().getStmts();

        for (int i = 0; i < statements.size(); i++) {
            Stmt stmt = statements.get(i);
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
                    traceLocalDefinition(argument, apiClass, callerMethod, statements, i, newChain);
                }
            }
        }
    }

    private static boolean isTargetGetInstanceCall(AbstractInvokeExpr invokeExpr, String className) {
        return "getInstance".equals(invokeExpr.getMethodSignature().getName()) && isTargetApi(className);
    }

    private static void traceAlgorithmArgument(Value argument, String apiClass, SootMethod method, List<Stmt> statements, int statementIndex,
                                               LinkedList<String> callChain, String literalSource) {
        if (argument instanceof StringConstant) {
            String algorithm = ((StringConstant) argument).getValue();
            AlgorithmClassifier.classifyAlgorithm(apiClass, algorithm, callChain, literalSource);
        } else if (argument instanceof Local) {
            traceLocalDefinition(argument, apiClass, method, statements, statementIndex, callChain);
        }
    }

    private static boolean isTargetApi(String className) {
        return TARGET_CLASSES.contains(className);
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