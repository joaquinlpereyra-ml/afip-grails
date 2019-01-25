package afip.detectors

import afip.variables.NormalVariable
import afip.vulns.HardcodedCredentials
import afip.vulns.Vuln
import org.apache.commons.logging.LogFactory
import org.codehaus.groovy.ast.expr.ConstantExpression
import org.codehaus.groovy.ast.expr.VariableExpression

class HardcodedCredentialsDetector extends Detector {

    private static final log = LogFactory.getLog(this)
    // TODAY WE ONLY DETECT CREDENTIALS IN Config.groovy AND DataSource.groovy
    HardcodedCredentialsDetector() {
        super(HardcodedCredentials, [], [])
    }

    ArrayList<Vuln> detect(NormalVariable variable){
        if (!on) return []
        log.debug(["title": "starting detection", "vuln": "hardcoded credentials"])
        ArrayList<Vuln> vulns = new ArrayList<>()
        if(filePath.endsWith('Config.groovy') || filePath.endsWith('DataSource.groovy')) {
            if((variable.getName().contains("pwd") || variable.getName().contains("pass")) && !variable.getName().contains("env")){
                if(variable.getValue().getType().getText() == "java.lang.String" && variable.getValue().getText() != "" && !variable.getValue().getText().contains("DB")) {
                    HardcodedCredentials vuln = new HardcodedCredentials(filePath, variable.getNode().getLineNumber(), variable.getNode().getText())
                    vulns.add(vuln)
                }
                else if(variable.getValue() instanceof VariableExpression){
                    def originalVariable = variable.getScope().getVariableOfName(variable.getValue().getText())
                    if (originalVariable.getValue() instanceof ConstantExpression){
                        HardcodedCredentials vuln = new HardcodedCredentials(filePath, variable.getNode().getLineNumber(), variable.getNode().getText())
                        vulns.add(vuln)
                    }
                }
            }
        }
        return vulns
    }
}