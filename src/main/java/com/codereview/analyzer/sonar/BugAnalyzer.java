package com.codereview.analyzer.sonar;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Component;

import com.codereview.analyzer.AbstractJavaAnalyzer;
import com.codereview.model.CodeIssue;
import com.codereview.model.CodeIssue.IssueType;
import com.codereview.model.CodeIssue.Severity;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.stmt.ReturnStmt;

/**
 * Analyzer for potential bugs based on SonarQube rules.
 */
@Component
public class BugAnalyzer extends AbstractJavaAnalyzer {

    @Override
    public String getAnalyzerId() {
        return "sonar-bug";
    }

    @Override
    public String getAnalyzerName() {
        return "SonarQube Bug Analyzer";
    }

    @Override
    protected List<CodeIssue> analyzeCompilationUnit(Path filePath, CompilationUnit cu, String originalContent) {
        List<CodeIssue> issues = new ArrayList<>();

        // Check for null pointer dereference risks (S2259)
        issues.addAll(checkNullPointerDereference(filePath, cu, originalContent));

        // Check for String comparison with == (S4973)
        issues.addAll(checkStringComparison(filePath, cu, originalContent));

        // Check for return in finally block (S1143)
        issues.addAll(checkReturnInFinally(filePath, cu, originalContent));

        // Check for hashCode without equals (S1206)
        issues.addAll(checkHashCodeWithoutEquals(filePath, cu, originalContent));

        // Check for infinite loops (S2189)
        issues.addAll(checkInfiniteLoops(filePath, cu, originalContent));

        return issues;
    }

    private List<CodeIssue> checkNullPointerDereference(Path filePath, CompilationUnit cu, String content) {
        List<CodeIssue> issues = new ArrayList<>();

        cu.findAll(MethodCallExpr.class).forEach(methodCall -> {
            // Check if calling method on a potentially null value
            methodCall.getScope().ifPresent(scope -> {
                if (scope.toString().endsWith("orElse(null)") ||
                        scope.toString().contains("get()")) {
                    int lineNumber = methodCall.getBegin().map(b -> b.line).orElse(1);
                    issues.add(CodeIssue.builder()
                            .id(generateIssueId())
                            .ruleId("java:S2259")
                            .ruleName("Null pointers should not be dereferenced")
                            .severity(Severity.BLOCKER)
                            .type(IssueType.BUG)
                            .category("Null Pointer")
                            .filePath(filePath.toString())
                            .lineNumber(lineNumber)
                            .message("A NullPointerException could be thrown; the return value of this method may be null.")
                            .description("Dereferencing a potentially null pointer leads to NullPointerExceptions at runtime.")
                            .suggestion("Add null checks or use Optional.map() instead of get().")
                            .codeSnippet(extractCodeSnippet(content, lineNumber, 2))
                            .sonarQubeReference("https://rules.sonarsource.com/java/RSPEC-2259")
                            .effortMinutes(10.0)
                            .source(getAnalyzerId())
                            .build());
                }
            });
        });

        return issues;
    }

    private List<CodeIssue> checkStringComparison(Path filePath, CompilationUnit cu, String content) {
        List<CodeIssue> issues = new ArrayList<>();

        cu.findAll(BinaryExpr.class).forEach(binaryExpr -> {
            if (binaryExpr.getOperator() == BinaryExpr.Operator.EQUALS ||
                    binaryExpr.getOperator() == BinaryExpr.Operator.NOT_EQUALS) {

                String left = binaryExpr.getLeft().toString();
                String right = binaryExpr.getRight().toString();

                // Check if either side is a string literal or likely string variable
                boolean leftIsString = left.startsWith("\"") || left.contains("String") ||
                        left.toLowerCase().contains("name") || left.toLowerCase().contains("text");
                boolean rightIsString = right.startsWith("\"") || right.contains("String") ||
                        right.toLowerCase().contains("name") || right.toLowerCase().contains("text");

                if ((leftIsString || rightIsString) &&
                        !binaryExpr.getLeft().isNullLiteralExpr() &&
                        !binaryExpr.getRight().isNullLiteralExpr()) {

                    int lineNumber = binaryExpr.getBegin().map(b -> b.line).orElse(1);
                    issues.add(CodeIssue.builder()
                            .id(generateIssueId())
                            .ruleId("java:S4973")
                            .ruleName("Strings should not be compared using == or !=")
                            .severity(Severity.MAJOR)
                            .type(IssueType.BUG)
                            .category("String Comparison")
                            .filePath(filePath.toString())
                            .lineNumber(lineNumber)
                            .message("Use equals() to compare strings instead of == or !=.")
                            .description("Using == compares object references, not string content. " +
                                    "This often leads to unexpected behavior.")
                            .suggestion("Use .equals() or Objects.equals() for string comparison.")
                            .codeSnippet(extractCodeSnippet(content, lineNumber, 1))
                            .sonarQubeReference("https://rules.sonarsource.com/java/RSPEC-4973")
                            .effortMinutes(5.0)
                            .source(getAnalyzerId())
                            .build());
                }
            }
        });

        return issues;
    }

    private List<CodeIssue> checkReturnInFinally(Path filePath, CompilationUnit cu, String content) {
        List<CodeIssue> issues = new ArrayList<>();

        cu.findAll(com.github.javaparser.ast.stmt.TryStmt.class).forEach(tryStmt -> {
            tryStmt.getFinallyBlock().ifPresent(finallyBlock -> {
                List<ReturnStmt> returns = finallyBlock.findAll(ReturnStmt.class);
                if (!returns.isEmpty()) {
                    int lineNumber = returns.get(0).getBegin().map(b -> b.line).orElse(1);
                    issues.add(CodeIssue.builder()
                            .id(generateIssueId())
                            .ruleId("java:S1143")
                            .ruleName("Return statements should not occur in finally blocks")
                            .severity(Severity.BLOCKER)
                            .type(IssueType.BUG)
                            .category("Control Flow")
                            .filePath(filePath.toString())
                            .lineNumber(lineNumber)
                            .message("Remove this return statement from this finally block.")
                            .description("A return in a finally block will suppress any exception thrown in try or catch blocks.")
                            .suggestion("Move the return statement outside the finally block.")
                            .codeSnippet(extractCodeSnippet(content, lineNumber, 2))
                            .sonarQubeReference("https://rules.sonarsource.com/java/RSPEC-1143")
                            .effortMinutes(30.0)
                            .source(getAnalyzerId())
                            .build());
                }
            });
        });

        return issues;
    }

    private List<CodeIssue> checkHashCodeWithoutEquals(Path filePath, CompilationUnit cu, String content) {
        List<CodeIssue> issues = new ArrayList<>();

        cu.findAll(com.github.javaparser.ast.body.ClassOrInterfaceDeclaration.class).forEach(classDecl -> {
            List<MethodDeclaration> methods = classDecl.getMethods();

            boolean hasHashCode = methods.stream()
                    .anyMatch(m -> m.getNameAsString().equals("hashCode") && m.getParameters().isEmpty());
            boolean hasEquals = methods.stream()
                    .anyMatch(m -> m.getNameAsString().equals("equals") && m.getParameters().size() == 1);

            if (hasHashCode != hasEquals) {
                int lineNumber = classDecl.getBegin().map(b -> b.line).orElse(1);
                String missing = hasHashCode ? "equals()" : "hashCode()";
                issues.add(CodeIssue.builder()
                        .id(generateIssueId())
                        .ruleId("java:S1206")
                        .ruleName("hashCode and equals should be overridden together")
                        .severity(Severity.BLOCKER)
                        .type(IssueType.BUG)
                        .category("Object Contract")
                        .filePath(filePath.toString())
                        .lineNumber(lineNumber)
                        .message(String.format("This class overrides %s but not %s.",
                                hasHashCode ? "hashCode()" : "equals()", missing))
                        .description("If hashCode is overridden, equals must also be overridden and vice versa. " +
                                "Violating this contract breaks collections like HashSet and HashMap.")
                        .suggestion(String.format("Override %s to be consistent with %s.",
                                missing, hasHashCode ? "hashCode()" : "equals()"))
                        .codeSnippet(extractCodeSnippet(content, lineNumber, 2))
                        .sonarQubeReference("https://rules.sonarsource.com/java/RSPEC-1206")
                        .effortMinutes(30.0)
                        .source(getAnalyzerId())
                        .build());
            }
        });

        return issues;
    }

    private List<CodeIssue> checkInfiniteLoops(Path filePath, CompilationUnit cu, String content) {
        List<CodeIssue> issues = new ArrayList<>();

        // Check for while(true) without break
        cu.findAll(com.github.javaparser.ast.stmt.WhileStmt.class).forEach(whileStmt -> {
            if (whileStmt.getCondition().toString().equals("true")) {
                boolean hasBreak = !whileStmt.getBody().findAll(com.github.javaparser.ast.stmt.BreakStmt.class).isEmpty();
                boolean hasReturn = !whileStmt.getBody().findAll(ReturnStmt.class).isEmpty();
                boolean hasThrow = !whileStmt.getBody().findAll(com.github.javaparser.ast.stmt.ThrowStmt.class).isEmpty();

                if (!hasBreak && !hasReturn && !hasThrow) {
                    int lineNumber = whileStmt.getBegin().map(b -> b.line).orElse(1);
                    issues.add(CodeIssue.builder()
                            .id(generateIssueId())
                            .ruleId("java:S2189")
                            .ruleName("Loops should not be infinite")
                            .severity(Severity.BLOCKER)
                            .type(IssueType.BUG)
                            .category("Control Flow")
                            .filePath(filePath.toString())
                            .lineNumber(lineNumber)
                            .message("Add an exit condition to this loop.")
                            .description("An infinite loop without a break, return, or throw will cause " +
                                    "the program to hang indefinitely.")
                            .suggestion("Add a break condition, return statement, or timeout mechanism.")
                            .codeSnippet(extractCodeSnippet(content, lineNumber, 3))
                            .sonarQubeReference("https://rules.sonarsource.com/java/RSPEC-2189")
                            .effortMinutes(30.0)
                            .source(getAnalyzerId())
                            .build());
                }
            }
        });

        return issues;
    }
}
