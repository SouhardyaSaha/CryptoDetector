package ast;

import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.VariableDeclarationExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.github.javaparser.resolution.declarations.ResolvedValueDeclaration;

import java.util.Optional;
import java.util.Set;

/**
 * Visitor that traverses the AST to find and analyze cryptographic API calls.
 * Identifies method calls to cryptographic classes and extracts algorithm information.
 */
public class CryptoAPIVisitor extends VoidVisitorAdapter<Void> {

    private static final Set<String> TARGET_CLASSES = Set.of(
            "Cipher", "MessageDigest", "KeyPairGenerator", "KeyGenerator"
    );

    @Override
    public void visit(MethodCallExpr n, Void arg) {
        super.visit(n, arg);

        if (n.getNameAsString().equals("getInstance") && n.getArguments().isNonEmpty()) {
            n.getScope().ifPresent(scope -> {
                if (TARGET_CLASSES.contains(scope.toString())) {
                    Expression argument = n.getArgument(0);

                    if (n.getRange().isPresent()) {
                        int lineNum = n.getRange().get().begin.line;

                        // Case A: Direct String Literal (e.g., "RSA")
                        if (argument.isStringLiteralExpr()) {
                            String algorithm = argument.asStringLiteralExpr().getValue();
                            AlgorithmClassifier.classifyAlgorithm(scope.toString(), algorithm, lineNum);
                        }
                        // Case B: Variable requiring Backward Dataflow Analysis
                        else if (argument.isNameExpr()) {
                            resolveAndClassifyVariable(argument, scope.toString(), lineNum);
                        }
                    }
                }
            });
        }
    }

    /**
     * Resolves a variable and classifies the algorithm it contains.
     *
     * @param argument the variable expression to resolve
     * @param apiClass the cryptographic API class name
     * @param lineNum the line number where the variable is used
     */
    private void resolveAndClassifyVariable(Expression argument, String apiClass, int lineNum) {
        try {
            ResolvedValueDeclaration resolvedValue = argument.asNameExpr().resolve();
            Optional<Node> astNode = resolvedValue.toAst();

            if (astNode.isEmpty()) {
                System.err.println("Line " + lineNum + ": Could not resolve variable '" + argument + "'");
                return;
            }

            Node node = astNode.get();

            // Handle multiple variables on a single line (VariableDeclarationExpr)
            if (node instanceof VariableDeclarationExpr varDeclExpr) {
                for (VariableDeclarator varDecl : varDeclExpr.getVariables()) {
                    if (varDecl.getNameAsString().equals(argument.toString())) {
                        processVariableDeclarator(varDecl, apiClass, lineNum);
                    }
                }
            }
            // Handle single variable declarations
            else if (node instanceof VariableDeclarator varDecl) {
                processVariableDeclarator(varDecl, apiClass, lineNum);
            }
        } catch (Exception e) {
            System.err.println("Line " + lineNum + ": Could not resolve variable '" + argument + "': " + e.getMessage());
        }
    }

    /**
     * Processes a variable declarator and extracts the algorithm value.
     *
     * @param varDecl the variable declarator to process
     * @param apiClass the cryptographic API class name
     * @param lineNum the line number where the variable is used
     */
    private void processVariableDeclarator(VariableDeclarator varDecl, String apiClass, int lineNum) {
        if (varDecl.getInitializer().isPresent() && varDecl.getInitializer().get().isStringLiteralExpr()) {
            String resolvedAlgorithm = varDecl.getInitializer().get().asStringLiteralExpr().getValue();
            AlgorithmClassifier.classifyAlgorithm(apiClass, resolvedAlgorithm, lineNum);
        }
    }
}

