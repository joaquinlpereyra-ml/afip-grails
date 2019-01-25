package afip.variables

import afip.scopes.Scope
import afip.utils.Create
import org.codehaus.groovy.ast.expr.EmptyExpression
import org.codehaus.groovy.ast.expr.Expression

class UnknownVariable extends NormalVariable {
    UnknownVariable(Expression expression, Scope scope, Integer branches) {
        setFields(expression.getText(), new EmptyExpression(), expression, scope, branches)
        this.name = expression.getText()
        this.node = expression
        this.value = Create.variableExpression(expression.getText())
    }

}
