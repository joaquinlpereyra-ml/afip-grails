package afip.vulns

/**
 * A bad configuration can open the door to many vulnerabilities, so it is considered one.
 * @field reason: why is this config a vda idea
 * @field solution: how you probably need to fix this
 */
class BadConfigVuln extends Vuln{

    static String getName(){
        return "Default encoding set to None"
    }

    BadConfigVuln(String filePath, int lineNumber, String code) {
        super(filePath, lineNumber, code)
        setReason("This bad configuration leads to an application being extremely vulnerable against XSS")
        setSolution("Change the configuration value to 'html', like this: grails.view.default.codec = 'html'`")
        setFriendlyName("Default encoding set to None")
        setCriticality("medium")
        setInformation("Setting the codec to 'none' disables safe-encoding HTML encoding by default, and leaves the application vulnerable to Reflected Cross-Site Scripting attacks.\n" +
                "Reflected Cross-Site Scripting (Reflected XSS) may lead to easier phishing, stolen cookies or a number of other issues.\n")
        setConfidence("high")
    }
}