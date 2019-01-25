package afip.detectors

import afip.variables.CollectionEntry
import afip.variables.CollectionVariable
import afip.vulns.MassAssignment
import org.apache.commons.logging.LogFactory

class MassAssignmentDetector extends Detector {


    private static final log = LogFactory.getLog(this)

    MassAssignmentDetector() {
        super(MassAssignment, [], [])
    }

    ArrayList<MassAssignment> detect(CollectionVariable constructorCall) {
        if (!on) return []
        log.debug(["title": "starting detection", "vuln": "mass assignment", "node": constructorCall.getNode().getText()])
        if (isConstructor(constructorCall) && argumentIsParams(constructorCall)) {
            return [new MassAssignment(filePath, constructorCall.getNode().getLineNumber(), constructorCall.getNode().getText())]
        }
        return []
    }

    private Boolean isConstructor(CollectionVariable c) {
        // when converting method calls to a binary expression of the form
        // methodCallName = [0: firstArg, 1: secondArg, ...]
        // we loose the ability to distingish between method calls and constructor calls,
        // so this is the best i could think of without changing the underlaying logic
        return c.getName().charAt(0).isUpperCase()
    }

    private Boolean argumentIsParams(CollectionVariable c) {
        if (c.getEntries().empty) { return false }
        for (CollectionEntry entry : c.getEntries().flatten()) {
            if (entry.getValue().getText() == 'params') {
                return true
            }
        }
        return false
    }
}