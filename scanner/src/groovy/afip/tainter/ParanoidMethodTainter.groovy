package afip.tainter

import afip.main.MethodAnalyzer
import afip.variables.ParameterVariable
import afip.vulns.Vuln

class ParanoidMethodTainter extends MethodTainter {

    ParanoidMethodTainter(Collection<Class<? extends Vuln>> vulns, MethodAnalyzer analyzer){
        super(vulns,analyzer)
    }

    void inspectVariable(ParameterVariable parameterVariable) {
        for (Class< ? extends Vuln> vuln : getVulns()){
            parameterVariable.addTriggerableVuln(vuln)
        }
    }

}
