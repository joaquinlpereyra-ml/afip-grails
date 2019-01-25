package afip.variables

import afip.vulns.Vuln

interface Taintable extends Dangerous {
    void addTriggerableVuln(Class<Vuln> vulnClass)

    void removeTriggerableVuln(Class<Vuln> vulnClass)

    void addUntaintedBranchForVuln(Class<Vuln> vulnClass)

    Integer getUntaintedBranchesFor(Class<Vuln> vulnClass)
}
