package afip.detectors

import afip.variables.CollectionEntry
import afip.variables.CollectionVariable
import afip.variables.NormalVariable
import afip.variables.Variable
import afip.vulns.RemoteCodeExecution
import org.apache.commons.logging.LogFactory
import org.codehaus.groovy.ast.expr.DeclarationExpression

class RemoteCodeExecutionDetector extends Detector {
    private static final log = LogFactory.getLog(this)

    RemoteCodeExecutionDetector() {
        super(RemoteCodeExecution, ['execute', 'start'], ['isSafeCommand'])
    }

    ArrayList<RemoteCodeExecution> detect(CollectionVariable methodCall) {
        log.debug(["title": "starting detection", "vuln": "remote code execution", "node": methodCall.getNode().getText()])
        if (!on) return []
        if (!isSink(methodCall.getEntry("receiver0")?.getName(), methodCall.getName(), methodCall.getScope())) { return [] }

        switch(methodCall.getName()) {
            case "execute":
                return handleExecuteMethodCall(methodCall)
            case "start":
                return handleStartMethodCall(methodCall)
            default:
                return []
        }
    }

    private RemoteCodeExecution handleDirectExecution(CollectionVariable methodCall) {
        if (methodCall.getEntry("receiver0").canTrigger(RemoteCodeExecution)) {
            return new RemoteCodeExecution(filePath, methodCall.getNode().getLineNumber(), methodCall.getNode().getText())
        }
    }

    private ArrayList<RemoteCodeExecution> handleExecuteMethodCall(CollectionVariable methodCall){
        if(!(methodCall.getEntry("receiver0"))) return []
        def receiver = methodCall.getEntry("receiver0") as CollectionEntry
        if (!(receiver.getVariable() instanceof NormalVariable)) return []
        def receiverVariable = receiver.getVariable() as NormalVariable

        def text = methodCall.getNode().getText()
        if (text.toLowerCase().contains("http") || text.toLowerCase().contains("request")) { return [] }
        if (methodCall.getEntry("receiver0").getValue().getText().contains("Service")) { return [] }
        if (!receiverVariable.getScope().canAccessVariable(receiverVariable.getValue().getText())) {
            if (receiverVariable.getTriggerableVulns().contains(RemoteCodeExecution)) {
                 return [new RemoteCodeExecution(filePath, methodCall.getNode().getLineNumber(), methodCall.getNode().getText())]
            }
            def vuln = handleDirectExecution(methodCall)
            return vuln ? [vuln] : []
        }

        receiverVariable = methodCall.getScope().getVariableOfName(receiverVariable.getValue().getText())
        def definitions = receiverVariable.getAllLivingDefinitions() as ArrayList<Variable>
        for (defs in definitions ) {
            if (!(defs.getNode() instanceof DeclarationExpression)) { continue }
            def node = defs.getNode() as DeclarationExpression
            def declaration = node.getLeftExpression()
            if (declaration.getType().getText() == "java.lang.String" || declaration.getType().getText() == "java.lang.Object") {
                def vuln = handleDirectExecution(methodCall)
                return vuln ? [vuln] : []
            }

        }
        return []
    }
    private ArrayList<RemoteCodeExecution> handleStartMethodCall(CollectionVariable methodCall){
        def vuln = handleDirectExecution(methodCall)
        return vuln ? [vuln] : []
    }
}