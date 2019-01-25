package afip.detectors

import afip.scopes.Scope
import afip.variables.CollectionVariable
import afip.variables.Variable
import afip.vulns.XmlExternalEntitiesAttack
import org.apache.commons.logging.LogFactory

class XmlExternalEntitiesAttackDetector extends Detector {
    private static final log = LogFactory.getLog(this)

    XmlExternalEntitiesAttackDetector() {
        super(XmlExternalEntitiesAttack, [], [])
    }

    ArrayList<XmlExternalEntitiesAttack> detect(CollectionVariable methodCall) {
        if (!on) return []
        log.debug(["title": "starting detection", "vuln": "xml external entities", "node": methodCall.getNode().getText()])
        Scope scope = methodCall.getScope()
        Variable var = methodCall.getEntry("receiver0")
        Variable referencedVariable = var ? scope.safelyGetVariableOfName(var.getValue().getText()) : null
        if (! (var && referencedVariable)) { return [] }
        ArrayList<Variable> originalMeanings = referencedVariable.getOriginalVariables()
        if (originalMeanings.collect { it.getValue().getText() }.contains("new XmlSlurper()") && methodCall.canTrigger(XmlExternalEntitiesAttack)) {
            return [new XmlExternalEntitiesAttack(filePath, methodCall.getNode().getLineNumber(), methodCall.getNode().getText())]
        }
        return []
    }
}
