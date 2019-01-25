package afip.variables

import afip.scopes.Scope
import afip.utils.Create
import org.codehaus.groovy.ast.Parameter
import org.codehaus.groovy.ast.expr.EmptyExpression

class ParameterVariable extends NormalVariable implements Taintable {
    ParameterVariable(Parameter parameter, Scope scope) {
        super(Create.assignmentFromTemplate(parameter.getName(), new EmptyExpression(), parameter), scope, 1)
    }
}
