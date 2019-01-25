package afip.detectors

import afip.variables.NormalVariable
import afip.vulns.HardcodedAdminToken
import afip.vulns.Vuln
import org.apache.commons.logging.LogFactory

class HardcodedAdminTokenDetector extends Detector {

    private static final log = LogFactory.getLog(this)

    HardcodedAdminTokenDetector() {
        super(HardcodedAdminToken, [], [])
    }

    ArrayList<Vuln> detect(NormalVariable variable){
        if (!on) return []
        log.debug(["title": "starting detection", "vuln": "hardcoded admin token"])
        ArrayList<Vuln> vulns = new ArrayList<>()
        if(variable.getValue().getText().startsWith("ADM-")) {
            HardcodedAdminToken vuln = new HardcodedAdminToken(filePath, variable.getNode().getLineNumber(), variable.getNode().getText())
            vulns.add(vuln)
        }
        return vulns
    }
}