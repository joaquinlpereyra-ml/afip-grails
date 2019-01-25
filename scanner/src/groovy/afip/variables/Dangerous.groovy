package afip.variables

import afip.scopes.Scope
import afip.vulns.Vuln

interface Dangerous {
    String getName()
    Scope getScope()
    Integer amountOfLivingDefinitions()
    Boolean canTrigger(Class<Vuln> vulnClass)
    HashSet<Class<Vuln>> getTriggerableVulns()
    HashSet<Class<Vuln>> getAllTriggerableVulns()
}
