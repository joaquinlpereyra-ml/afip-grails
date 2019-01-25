package afip.variables

import afip.scopes.Scope
import afip.utils.Create
import org.codehaus.groovy.ast.stmt.ReturnStatement

/**
 * ReturnVariable represents return statements on methods. Our motivation for this is to analyzeMethod
 * the taint being returned by the method invoked, i.e. return params.evil should be represented
 * with return = params.evil, so return as tainted as params.evil
**/
class ReturnVariable extends NormalVariable implements Taintable {
    ReturnVariable(ReturnStatement returnStatement, Scope scope){
        super(Create.assignmentFromTemplate("return",returnStatement.getExpression(),returnStatement), scope, 1)
    }
}
