package afip.variables

import afip.scopes.Scope
import afip.utils.Extract
import afip.vulns.Vuln
import org.codehaus.groovy.ast.expr.BinaryExpression

class NormalVariable extends Variable implements Taintable {

    NormalVariable() {}

    NormalVariable(BinaryExpression binaryExpression, Scope scope, Integer branches) {
        setFields(Extract.variableName(binaryExpression), binaryExpression.getRightExpression(), binaryExpression, scope, branches)
    }

    void addUntaintedBranchForVuln(Class<Vuln> vulnClass) {
        for (Variable variable : getAllDefinitions()) {
            variable.untaintedBranches[vulnClass] = variable.untaintedBranches[vulnClass] + 1
        }
    }

    void addTriggerableVuln(Class<Vuln> vulnClass) {
        _triggerableVulns.add(vulnClass)
    }

    void removeTriggerableVuln(Class<Vuln> vulnClass) {
        for (Variable variable : getAllDefinitions()) {
            variable._triggerableVulns.remove(vulnClass)
        }
    }

    Boolean canTrigger(Class<Vuln> vulnClass) {
        getAllTriggerableVulns().contains(vulnClass)
    }

    Integer getUntaintedBranchesFor(Class<Vuln> vulnClass) {
        return untaintedBranches.get(vulnClass)
    }

    HashSet<Class<Vuln>> getAllTriggerableVulns() {
        HashSet<Class<Vuln>> allTriggerableVulns = new HashSet<Class<Vuln>>()
        for (Variable variable : getAllLivingDefinitions()) {
            allTriggerableVulns.addAll(variable.getTriggerableVulns())
        }
        return allTriggerableVulns
    }

    HashSet<Class<Vuln>> getTriggerableVulns() {
        return _triggerableVulns
    }
}
