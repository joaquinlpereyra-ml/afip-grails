package afip.vulns

class MassAssignment extends Vuln {

    static String getName(){
        return "Mass Assignment"
    }

    MassAssignment(String filePath, int lineNumber, String code) {
        super(filePath, lineNumber, code)
        setFriendlyName("Mass Assignment")
        setConfidence("high")
        setInformation("This may be used by an attacker to set fields on the object, including private or protected ones.\n" +
                "That may lead to an attacker controlling bussiness logic.\n" +
                "Avoid using whole dictionaries or collection of user-controlled variables to create instances.\n")
        setIsVuln(false)
        setCriticality("low")
    }
}
