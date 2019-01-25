package afip.vulns

class HardcodedCredentials extends Vuln {

    static String getName(){
        return "Hardcoded credentials"
    }

    HardcodedCredentials(String filePath, int lineNumber, String code) {
        super(filePath, lineNumber, code)
        setFriendlyName("Hardcoded credentials")
        setConfidence("high")
        setInformation("If this code is leaked, it may give access to an attacker to our private systems.\n" +
                "Even if the credential is of a local database, it may give insight into what kind of passwords the team uses.\n" +
                "For local services, use env variables to store the information. For other kind of services, please" +
                "refer to the specific service documentation.\n" +
                "There may be services which at the moment do not have an easy solution to this. In that case, ignore" +
                "the report until a solution is announced.\n")
        setIsVuln(false)
        setCriticality("low")
    }

}