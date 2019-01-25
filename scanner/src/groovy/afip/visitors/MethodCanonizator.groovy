package afip.visitors

import afip.utils.Create
import org.codehaus.groovy.ast.MethodNode
import org.codehaus.groovy.ast.expr.*
import org.codehaus.groovy.ast.stmt.ReturnStatement
import org.codehaus.groovy.classgen.ReturnAdder

class MethodCanonizator {
    private ReturnAdder returnAdder = new ReturnAdder()

    MethodCanonizator() { }

    /** Visit the methods and add implicit returns to each one of those */
    void visit(ArrayList<MethodNode> methods) {
        for (MethodNode method : methods) {
            returnAdder.visitMethod(method)
            addRenderToReturns(method)
        }
    }

    void addRenderToReturns(MethodNode method) {

        BasicVisitor visitor = new BasicVisitor() {
            HashMap<ReturnStatement, Boolean> addsAMap = new HashMap<>()

            void visitReturnStatement(ReturnStatement returnStatement) {
                addsAMap.put(returnStatement, false)
                Expression returnExpression = returnStatement.getExpression()
                if (returnExpression instanceof MapExpression) {
                    addsAMap[returnStatement] = true
                }
            }
        }

        visitor.visit([method])
        for (ReturnStatement returnStatement : visitor.addsAMap.keySet()) {
            if (visitor.addsAMap[returnStatement]) {
                ConstantExpression modelConstantExpression = new ConstantExpression("model")
                NamedArgumentListExpression renderArguments = new NamedArgumentListExpression()
                renderArguments.addMapEntryExpression(modelConstantExpression, returnStatement.getExpression())
                MethodCallExpression renderMethodCall = Create.methodCall('render', renderArguments)
                returnStatement.setExpression(renderMethodCall)
            }
        }
    }
}
