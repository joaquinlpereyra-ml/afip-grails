package afip.vulns

/**
 * A bad encoding in a view can bypass correct configuration and allow XSS to pass by.
 * @field reason: why is this a bad idea
 * @field solution: how to fix it
 * @field filePath: the path of the view where this was found
 */
class BadEncodingVuln extends Vuln{

    static String getName(){
        return "Bad Encoding"
    }

    BadEncodingVuln(String filePath, int lineNumber, String code){
        super(filePath, lineNumber, code)
        setSolution("Change the encoding of this internationalization to 'html' and do not use old style .jsp expressions")
        setReason("This disables global encoding options and makes the application vulnerable to XSS")
        setFriendlyName("Bad Encoding")
        setConfidence("high")
        setCriticality("low")
        setInformation("This is vulnerable against Cross Site Scripting, which may lead to easier phishing or cookie compromise.\n" +
                "Please change the encoding of this internationalization to 'html' and do not use 'old style' .jsp expressions.\n")
        setIsVuln(false)
    }
}
