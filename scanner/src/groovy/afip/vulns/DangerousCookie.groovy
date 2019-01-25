package afip.vulns

class DangerousCookie extends Vuln {

    static String getName(){
        return "Dangerous cookie"
    }

    DangerousCookie(String filePath, int lineNumber, String code) {
        super(filePath, lineNumber, code)
        setFriendlyName("Dangerous cookie")
        setConfidence("medium")
        setInformation("This is dangerous because if an attacker steal it can control a user account")
        setInformation("This cookie is extremely sensitive as it gives control of an account to an attacker if gotten.\n" +
                "You should not need to use it.\n")
        setIsVuln(false)
        setCriticality("low")
    }
}