package afip.vulns

class SqlInjection extends Vuln {

    static String getName(){
        return "Sql injection"
    }

    SqlInjection(String filePath, int lineNumber, String code) {
        super(filePath, lineNumber, code)
        setFriendlyName("Sql injection")
        setConfidence("medium")
        setInformation("This can be used by an attacker to execute arbitrary commands on the SQL DB.\n" +
                "Avoid using the .find method directly or use prepared statements to avoid this.\n")
        setIsVuln(true)
        setCriticality("high")
    }
}