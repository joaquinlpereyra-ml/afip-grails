package afip.vulns

class HardcodedAdminToken extends Vuln {

    static String getName(){
        return "Hardcoded admin token"
    }

    HardcodedAdminToken(String filePath, int lineNumber, String code) {
        super(filePath, lineNumber, code)
        setFriendlyName("Hardcoded admin token")
        setConfidence("medium")
        setInformation("If this code is leaked, an attacker can use this token to gain access to our internal systems.\n")
        setIsVuln(false)
        setCriticality("low")
    }
}