package afip.visitors

import afip.errors.VariableNotFound
import afip.managers.BranchManager
import afip.scopes.Scope
import afip.utils.Create
import afip.utils.Extract
import afip.variables.Variable
import org.codehaus.groovy.ast.MethodNode
import org.codehaus.groovy.ast.expr.BinaryExpression
import org.codehaus.groovy.ast.expr.Expression
import org.codehaus.groovy.ast.expr.MapEntryExpression
import org.codehaus.groovy.ast.expr.MethodCallExpression
import org.codehaus.groovy.ast.stmt.ReturnStatement

class GetterVisitor extends BasicVisitor {
    private String methodName
    private MethodNode currentMethod
    private Scope scopes
    private BranchManager branchManager

    /**
     * Initialize the getter visitor.
     */
    GetterVisitor(Scope scopes, BranchManager branchManager) {
        this.branchManager = branchManager
        this.scopes = scopes
    }

    Scope getScopes(){
        scopes
    }
    /** Visit a gettterMethod. This better be a method starting with 'get' */
    void visit(ArrayList<MethodNode> getterMethods) {
        for (MethodNode getter : getterMethods) {
            assert getter.getName().startsWith('get')
            this.methodName = getter.getName()
            this.currentMethod = getter
            super.visit([getter])
        }
    }

    /** Visit the return statement and create and register a variable with its name */
    void visitReturnStatement(ReturnStatement returnStatement) {
        String variableName = methodName.split("get")[1]
        variableName = variableName.substring(0, 1).toLowerCase() + variableName.substring(1)

        // we need to consider those canonized methodNodes
        Expression returnExpression = returnStatement.getExpression()
        String expressionText = returnExpression.getText()
        if (returnExpression instanceof MethodCallExpression && returnExpression.getMethodAsString() == 'render') {
            returnExpression = returnExpression as MethodCallExpression
            ArrayList<MapEntryExpression> arguments = Extract.argumentsFromMethodCall(returnExpression)
            Expression key = arguments.find { it.getKeyExpression().getText() == 'model' }
            if (! key) { return }
            expressionText = key.getText()
            returnExpression = key.getValueExpression()
        }

        try {
            Variable var = getScopes().getLastDeclarationOf(expressionText)
            BinaryExpression fakeBinary = Create.assignmentFromTemplate(variableName, var.getValue(), var.getNode())
            Variable.createAndRegister(fakeBinary, branchManager.getAmountBranches(), getScopes())
        } catch (VariableNotFound ignored) {
            BinaryExpression fakeBinary = Create.assignmentFromTemplate(variableName, returnExpression, currentMethod)
            Variable.createAndRegister(fakeBinary, branchManager.getAmountBranches(), getScopes())
        }
    }
}

