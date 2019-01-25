package afip.vulns

class RemoteCodeExecution extends Vuln {

    static String getName(){
        return "Remote code execution"
    }

    RemoteCodeExecution(String filePath, int lineNumber, String code) {
        super(filePath, lineNumber, code)
        setFriendlyName("Remote code execution")
        setConfidence("high")
        setInformation("This can be used by an attacker to execute arbitrary commands on the server.\n" +
                "Do not use external executes or evals in your application.\n")
        setIsVuln(true)
        setCriticality("high")
    }
}