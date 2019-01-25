package afip.detectors

import afip.variables.NormalVariable
import afip.variables.Variable
import afip.vulns.Vuln
import afip.vulns.WeakCryptoVuln
import org.apache.commons.logging.LogFactory
import org.codehaus.groovy.ast.expr.BinaryExpression

class WeakCryptoDetector extends Detector{

    private static final log = LogFactory.getLog(this)

    WeakCryptoDetector(){
        super(WeakCryptoVuln, [], [])
    }


    ArrayList<Vuln> detect(NormalVariable variable){
        if (!on) return []
        log.debug(["title": "starting detection", "vuln": "weak crypto","variableType": "normalVariable"])
        ArrayList<Vuln> vulns = new ArrayList<>()
        if(!(variable.getNode() instanceof BinaryExpression)) {
            return []
        }
        vulns.addAll(searchInsecureHashing(variable))
        return vulns
    }

    ArrayList<Vuln> detect(Variable variable) {
        if (!on) return []
        log.debug(["title": "starting detection", "vuln": "weak crypto","variableType":"variable"])
        if(!(variable.getNode() instanceof BinaryExpression)) {
            return []
        }
        ArrayList<WeakCryptoVuln> weakCryptoVulns = searchInsecureHashing(variable)
        return weakCryptoVulns
    }

    ArrayList<WeakCryptoVuln> searchInsecureHashing(Variable variable) {
        ArrayList<WeakCryptoVuln> vulns = new ArrayList<>()
        BinaryExpression expression = variable.getNode() as BinaryExpression
        ArrayList<String> brokenHashingMethods = ["md2","md4","md5"]
        ArrayList<String> weakHashingMethods = ["sha1"]

        for(String hashingName : brokenHashingMethods) {
            if (variable.getName().toLowerCase().contains(hashingName)) {
                String reason = "This represents a potential insecure hash."
                String solution = "Change to another cryptographic algorithm."
                WeakCryptoVuln vuln = new WeakCryptoVuln(reason, filePath, expression.getLineNumber(), expression.getText(), solution)
                vulns.add(vuln)
            }
        }

        for(String hashingName : weakHashingMethods) {
            if (variable.getName().toLowerCase().contains(hashingName)) {
                String reason = "This represents a posible insecure hash"
                String solution = "Think about if it's possible change to another cryptographic algorithm."
                WeakCryptoVuln vuln = new WeakCryptoVuln(reason, filePath, expression.getLineNumber(), expression.getText(), solution)
                vulns.add(vuln)
            }
        }
        return vulns
    }
}
