package afip.detectors

import afip.variables.CollectionEntry
import afip.variables.CollectionVariable
import afip.vulns.OpenRedirect
import org.apache.commons.logging.LogFactory

class OpenRedirectDetector extends Detector {
    private static final log = LogFactory.getLog(this)

    OpenRedirectDetector() {
        super(OpenRedirect, ['redirect'], ['isValidURL', 'isValidRedirect', 'isValidDomain'])
    }

    ArrayList<OpenRedirect> detect(CollectionVariable methodCall) {
        log.debug(["title": "starting detection", "vuln": "open redirect", "node": methodCall.getNode().getText()])
        if (!on) return []
        // mandatory conditions for a open redirect vulnerability to exist
        if (! filePath.endsWith("Controller.groovy")) { return [] }
        if (!isSink(methodCall.getEntry("receiver0")?.getName(), methodCall.getName(), methodCall.getScope())) { return [] }
        if (! (methodCall.getEntry('url') || methodCall.getEntry('uri'))) { return [] }
        if (urlFromConfig(methodCall)) { return [] }
        if (! (methodCall.canTrigger(OpenRedirect))) { return [] }

        return [new OpenRedirect(filePath, methodCall.getNode().getLineNumber(), methodCall.getNode().getText())]
    }

    static private urlFromConfig(CollectionVariable methodCall) {
        CollectionEntry entry = methodCall.getEntry("url") ?: methodCall.getEntry("uri")
        return (entry.getValue().getText()).toLowerCase().contains("grailsApplication.config".toLowerCase())
    }

}