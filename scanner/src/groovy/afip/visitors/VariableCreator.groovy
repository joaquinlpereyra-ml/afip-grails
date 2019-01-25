package afip.visitors

import afip.managers.BranchManager
import afip.scopes.Scope
import afip.utils.Ask
import afip.utils.Create
import afip.variables.Variable
import org.apache.commons.logging.LogFactory
import org.codehaus.groovy.ast.ASTNode
import org.codehaus.groovy.ast.FieldNode
import org.codehaus.groovy.ast.MethodNode
import org.codehaus.groovy.ast.Parameter
import org.codehaus.groovy.ast.expr.*
import org.codehaus.groovy.ast.stmt.IfStatement
import org.codehaus.groovy.ast.stmt.ReturnStatement
import org.codehaus.groovy.ast.stmt.SwitchStatement
import org.codehaus.groovy.ast.stmt.TryCatchStatement

class VariableCreator extends BasicVisitor {
    Scope scopes
    Scope currentMethodScope
    BranchManager branchManager
    private static final log = LogFactory.getLog(this)


    VariableCreator(Scope scopes, BranchManager branchManager) {
        this.scopes = scopes
        this.currentMethodScope = scopes
        this.branchManager = branchManager
    }

    void visit(ArrayList<ASTNode> astNodes) {
        for (ASTNode node : astNodes) {
            if (node instanceof FieldNode) {
                visitField(node)
                continue
            }
            if (!(node instanceof MethodNode)) {continue}
            currentMethodScope = scopes.createInnerScopeWith(node)
            visitConstructorOrMethod(node,false)
            currentMethodScope = currentMethodScope.getOuterScope()
        }
    }

    @Override
    void visitConstructorOrMethod(MethodNode method, boolean isConstructor) {
        log.debug(["title": "extracting variables", "from": "method", "code": method.getText()])
        for (Parameter parameter : method.getParameters()) {
            Variable.createAndRegister(parameter, branchManager.getAmountBranches(), currentMethodScope)
        }
        super.visitConstructorOrMethod(method, isConstructor)
    }

    @Override
    void visitBinaryExpression(BinaryExpression binaryExpression) {
        log.debug(["title": "extracting variables", "from": "binary expression", "code": binaryExpression.getText()])
        if (Ask.isVariable(binaryExpression)) {
            Variable.createAndRegister(binaryExpression, branchManager.getAmountBranches(), currentMethodScope)
        }
        super.visitBinaryExpression(binaryExpression)
    }

    @Override
    void visitMethodCallExpression(MethodCallExpression methodCallExpression) {
        // maybe surprisingly, method calls *can* and *do* commonly define afip.variables
        // see the function docs for more information
        //log.debug(["title": "extracting variables", "from": "method call", "code": methodCallExpression.getText()])
        Variable.createAndRegister(methodCallExpression, branchManager.getAmountBranches(), currentMethodScope)
        super.visitMethodCallExpression(methodCallExpression)
    }

    @Override
    void visitConstructorCallExpression(ConstructorCallExpression constructorCallExpression) {
        log.debug(["title": "extracting variables", "from": "construct call", "code": constructorCallExpression.getText()])
        Variable.createAndRegister(constructorCallExpression, branchManager.getAmountBranches(), currentMethodScope)
        super.visitConstructorCallExpression(constructorCallExpression)
    }

    @Override
    void visitField(FieldNode fieldNode) {
        log.debug(["title": "extracting variables", "from": "field expression", "code": fieldNode.getText()])
        Variable.createAndRegister(fieldNode, getBranchManager().getAmountBranches(), currentMethodScope)
    }

    @Override
    void visitClosureExpression(ClosureExpression closure) {
        log.debug(["title": "extracting variables", "from": "closure", "code": closure.getText()])
        Scope closureScope = currentMethodScope.createInnerScopeWith(closure)
        currentMethodScope = closureScope
        for (Parameter parameter : closure.getParameters()) {
            Variable.createAndRegister(parameter, branchManager.getAmountBranches(), closureScope)
        }
        if (! closure.getParameters()) {
            VariableExpression implicitIt = Create.variableExpression('it')
            Variable.createAndRegister(implicitIt, branchManager.getAmountBranches(), closureScope)
        }
        super.visitClosureExpression(closure)
        currentMethodScope = currentMethodScope.getOuterScope()
    }

    @Override
    void visitIfElse(IfStatement ifStatement) {
        if (!Ask.endsInmediatly(ifStatement)) {
            branchManager.enterNewBranching()
        }
        super.visitIfElse(ifStatement)
        if (!Ask.endsInmediatly(ifStatement)) {
            branchManager.leaveBranching()
        }
    }

    @Override
    void visitSwitch(SwitchStatement switchStatement) {
        branchManager.enterNewBranching(switchStatement)
        super.visitSwitch(switchStatement)
        branchManager.leaveBranching(switchStatement)
    }

    @Override
    void visitTryCatchFinally(TryCatchStatement tryCatchStatement) {
        branchManager.enterNewBranching()
        super.visitTryCatchFinally(tryCatchStatement)
        branchManager.leaveBranching()
    }

    @Override
    void visitTernaryExpression(TernaryExpression ternaryExpression) {
        branchManager.enterNewBranching()
        super.visitTernaryExpression(ternaryExpression)
        branchManager.leaveBranching()
    }

    @Override
    void visitReturnStatement(ReturnStatement returnStatement){
        Variable.createAndRegister(returnStatement, branchManager.getAmountBranches(), currentMethodScope)
        super.visitReturnStatement(returnStatement)
    }
}
