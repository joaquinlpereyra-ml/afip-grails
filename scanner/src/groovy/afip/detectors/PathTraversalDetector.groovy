package afip.detectors

import afip.variables.CollectionEntry
import afip.variables.CollectionVariable
import afip.variables.NormalVariable
import afip.variables.Variable
import afip.vulns.PathTraversal
import org.apache.commons.logging.LogFactory
import org.codehaus.groovy.ast.expr.ConstructorCallExpression
import org.codehaus.groovy.ast.expr.Expression

class PathTraversalDetector extends Detector {
    private static final log = LogFactory.getLog(this)

    PathTraversalDetector() {
        super(PathTraversal, [], ['isValidPath', 'getCanonicalPath'])
    }

    ArrayList<PathTraversal> detect(CollectionVariable methodCall) {
        log.debug(["title": "starting detection", "vuln": "path traversal", "node": methodCall.getNode().getText()])
        if (!on) return []

        if(!(methodCall.getEntry("receiver0"))) return []
        if(methodCall.getName() in getDefaultCleaners()) return []

        def receiver = methodCall.getEntry("receiver0") as CollectionEntry
        if (!(receiver.getVariable() instanceof NormalVariable)) return []

        def receiverVariable = receiver.getVariable() as NormalVariable

        if (receiverVariable.getScope().canAccessVariable(receiverVariable.getValue().getText())) {
            receiverVariable = methodCall.getScope().getVariableOfName(receiverVariable.getValue().getText())
            def declarations = receiverVariable.getOriginalVariables() as ArrayList<Variable>
            for (defs in declarations ){
                def declarationVar = methodCall.getScope().getVariableOfName(receiverVariable.getName())
                if (!(declarationVar instanceof NormalVariable)) continue
                declarationVar = declarationVar as NormalVariable
                def declarationVarRightSide = declarationVar.getValue()
                if (!(declarationVarRightSide instanceof ConstructorCallExpression)) { continue }
                if (!(declarationVarRightSide.getArguments()[0])) { continue }
                def argument = declarationVarRightSide.getArguments()[0] as Expression
                def argumentName = argument.getText()
                def argumentVariable
                if (methodCall.getScope().safelyGetVariableOfName(argumentName)) {
                    argumentVariable = methodCall.getScope().getVariableOfName(argumentName)
                }
                declarationVarRightSide = declarationVarRightSide as ConstructorCallExpression
                if (declarationVarRightSide.getType().getText() == 'File' && argumentVariable?.canTrigger(PathTraversal) || (!argumentVariable && declarationVar.canTrigger(PathTraversal))) {
                    return [new PathTraversal(filePath, methodCall.getNode().getLineNumber(), methodCall.getNode().getText())]
                }
            }
        }
        return []
    }
}