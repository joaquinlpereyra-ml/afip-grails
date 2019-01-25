package afip.detectors

import afip.variables.NormalVariable
import afip.vulns.DangerousCookie
import afip.vulns.Vuln
import org.apache.commons.logging.LogFactory

class DangerousCookieDetector extends Detector {

    private static final log = LogFactory.getLog(this)

    DangerousCookieDetector() {
        super(DangerousCookie, [], [])
    }

    ArrayList<Vuln> detect(NormalVariable variable) {
        if (!on) return []
        log.debug(["title": "starting detection", "vuln": "dangerous cookie"])
        ArrayList<Vuln> vulns = new ArrayList<>()
        if(variable.getValue().getText().toLowerCase().contains("orgid") || variable.getValue().getText().toLowerCase().contains("orgapi")){
            DangerousCookie vuln = new DangerousCookie(filePath, variable.getNode().getLineNumber(), variable.getNode().getText())
            vulns.add(vuln)
        }
        return vulns
    }
}