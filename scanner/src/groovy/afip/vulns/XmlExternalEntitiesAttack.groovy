package afip.vulns

class XmlExternalEntitiesAttack extends Vuln {

    static String getName(){
        return "XML external entities attack"
    }

    XmlExternalEntitiesAttack(String filePath, int lineNumber, String code) {
        super(filePath, lineNumber, code)
        setFriendlyName("XML external entities attack")
        setConfidence("high")
        setInformation("This can be used by an attacker to perform a DoS or read sensitive data.\n" +
                "Call the the 'setFeature' method on your XmlSlurper before using it with parameters: ('http://xml.org/sax/features/external-general-entities', false) to fix this.\n")
        setIsVuln(true)
        setCriticality("high")
    }
}