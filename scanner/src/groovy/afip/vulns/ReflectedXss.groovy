package afip.vulns


class ReflectedXss extends Vuln {
    String type // valid types are 'maybe, redirect, model, text'

    static String getName(){
        return "Reflected XSS"
    }

    private HashMap<String, HashMap<String, String>> messages = new HashMap<>(
            maybe: [
                    confidence: 'low',
                    message: "You are rendering a a model which took input from the user, " +
                            "but the tool could not find an usage of this input in the view.\n" +
                            "This finding though reveals the default enconding of the application is 'none', you" +
                            "should change it to HTML. There should be another issue raised which relates to the encoding!\n" +
                            "This will fix most of the Reflected XSS issues.\n"
            ],
            redirect: [
                    confidence: 'medium',
                    message: "You have a vulnerable redirect which takes input from the user.\n" +
                            "This may lead to account compromise or easier phishing for attacker.\n" +
                            "Correct the default encoding of your application and set it to 'html'\n" +
                            "This will fix most of the Reflected XSS issues\n."
            ],
            model: [
                    confidence: 'high',
                    message: "You are rendering a model which takes input from the user.\n " +
                            "Correct the default encoding of your application and set it to 'html'\n" +
                            "This will fix most of the Reflected XSS issues\n."
            ],

            view: [
                    confidence: 'high',
                    message: "You are using params in your view and your encoding is incorrect!\n" +
                            "Correct the default encoding of your application and set it to 'html'\n" +
                            "This will fix most of the Reflected XSS issues\n."
            ],
            text: [
                    confidence: 'high',
                    message: "You are rendering a text with input from the user.\n" +
                            "Correct the default encoding of your application and set it to 'html'\n" +
                            "This will fix most of the Reflected XSS issues\n."
            ]
    )

    ReflectedXss(String xssCategory, String filePath, int lineNumber, String code) {
        super(filePath, lineNumber,code)
        assert (xssCategory == 'maybe' || xssCategory == 'redirect' || xssCategory == 'model' || xssCategory == 'view' || xssCategory == 'text')

        setIsVuln(true)
        setReason("This vulnerability leads to arbitrary JS code execution on the client side")
        setSolution("Correctly encode the output of your Grails application")
        setConfidence(messages[xssCategory]['confidence'])
        setInformation(messages[xssCategory]['message'])
        setFriendlyName("Reflected XSS")
        setCriticality("high")
    }
}
