package afip.detectors

import afip.variables.CollectionEntry
import afip.variables.CollectionVariable
import afip.vulns.SqlInjection
import org.apache.commons.logging.LogFactory

class SqlInjectionDetector extends Detector {
    private static final log = LogFactory.getLog(this)

    SqlInjectionDetector() {
        super(SqlInjection, ['execute', 'find'], [])
    }

    ArrayList<SqlInjection> detect(CollectionVariable methodCall) {
        log.debug(["title": "starting detection", "vuln": "sql injection", "node": methodCall.getNode().getText()])
        if (!on) { return [] }
        if (!isSink(methodCall.getEntry("receiver0")?.getName(), methodCall.getName(), methodCall.getScope())) { return [] }
        ArrayList<SqlInjection> vulns = []
        vulns.add(sqlInFind(methodCall))
        vulns.add(sqlExecute(methodCall))
        return vulns.findAll { it != null }
    }

    SqlInjection sqlInFind(CollectionVariable methodCall) {
        if (!methodCall.getEntry("0")) { return }
        if (methodCall.getName() != 'find') { return }
        if (methodCall.getEntry("receiver0").getValue().getText().contains("Service")) { return }
        if (usesMoreThanOneParameter(methodCall)) { return }
        if (!methodCall.getEntry("0").canTrigger(SqlInjection)) { return }

        return new SqlInjection(filePath, methodCall.getNode().getLineNumber(), methodCall.getNode().getText())
    }

    SqlInjection sqlExecute(CollectionVariable methodCall) {
        if (!methodCall.getEntry("0")) { return }
        if (! methodCall.getName().startsWith('execute')) { return }
        if (usesMoreThanOneParameter(methodCall)) { return }
        if (!methodCall.getEntry("0").canTrigger(SqlInjection)) { return }
        def var = methodCall.getScope().safelyGetVariableOfName(methodCall.getEntry("receiver0").getValue().getText())
        if (!var) { return }
        if (!(var.getValue().getText().startsWith("new Sql"))) { return }
        return new SqlInjection(filePath, methodCall.getNode().getLineNumber(), methodCall.getNode().getText())
    }

    private Boolean usesMoreThanOneParameter(CollectionVariable methodCall) {
        ArrayList<CollectionEntry> entries = methodCall.getEntries().flatten()
        return entries.collect { it.getName() }.findAll { !it.startsWith("receiver") }. size() > 1
    }
}