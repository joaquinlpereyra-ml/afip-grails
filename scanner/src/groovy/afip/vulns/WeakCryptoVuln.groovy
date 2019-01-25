package afip.vulns


class WeakCryptoVuln extends Vuln {

    static String getName(){
        return "Weak Hashing Method"
    }

    WeakCryptoVuln(String message, String filePath, int lineNumber, String code, String possibleSolution) {
        super(filePath, lineNumber, code)
        this.filePath = filePath
        setIsVuln(false)
        setReason(message)
        setSolution(possibleSolution)
        setConfidence("medium")
        setFriendlyName("Weak Hashing method")
        setCriticality("medium")
        setInformation("This hashing method can be broken and must be avoided.\n" +
                "If you just need a random value (example, an ID), use UUID V4.\n" +
                "If you really need a hash, avoid MD5 and SHA1.")
    }
}
