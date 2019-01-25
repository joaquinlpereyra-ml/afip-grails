package afip.vulns

class PathTraversal extends Vuln {

    static String getName(){
        return "Path traversal"
    }

    PathTraversal(String filePath, int lineNumber, String code) {
        super(filePath, lineNumber, code)
        setFriendlyName("Path traversal")
        setConfidence("high")
        setInformation("This enables an attacker to manipulate to target a file on the system.\n" +
                "It may lead to leakeage of senstive data, credential compromise or even manipulation of the app's behavior.\n" +
                "Pass the file path through a validator of name 'isValidPath' wich validates the input before it reaches the File class\n" +
                "or before the instance is consumed by a method like 'Read'.\n" +
                "Example:\n" +
                "def foo() {" +
                "def path = params path\n" +
                "   if (!isValidPath(path)) {\n" +
                "       throw new BadRequestException(path)\n" +
                "   }\n" +
                "   return file.size()\n" +
                "}\n")
        setIsVuln(true)
        setCriticality("high")
    }
}