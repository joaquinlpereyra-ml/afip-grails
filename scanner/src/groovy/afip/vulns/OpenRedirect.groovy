package afip.vulns

class OpenRedirect extends Vuln {

    static String getName(){
        return "Open Redirect"
    }

    OpenRedirect(String filePath, int lineNumber, String code) {
        super(filePath, lineNumber, code)
        setFriendlyName("Open Redirect")
        setIsVuln(true)
        setCriticality("medium")
        setInformation("This can be used by an attacker to redirect a victim to another site.\n" +
                "This, in turn, allows the attacker to send the victim to a phishing URL almost transparently.\n" +
                "Pass the URL you're redirecting to through a validator method with the name of isValidURL, isValidDomain or isValidRedirect.\n" +
                "Example:\n" +
                "```\n" +
                "def url = params.url\n" +
                "if (!(utils.isValidURL(url)) {\n" +
                "   url = 'https://mercadolibre.com'\n" +
                "}\n" +
                "redirect(url: url}\n" +
                "```")
        setConfidence("high")
    }
}