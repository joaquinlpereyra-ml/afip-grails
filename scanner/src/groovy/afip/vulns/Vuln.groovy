package afip.vulns

import org.apache.commons.logging.LogFactory

/**
 * IMPORTANT! UPDATE THIS CLASS WHEN ADDING NEW VULNERABILITIES.
 *
 * An abstract class to represent all the vulnerabilities.
 */
abstract class Vuln {
    String filePath
    String code
    Integer lineNumber
    String message
    String solution
    String reason
    String friendlyName
    String confidence
    String information
    Boolean isVuln
    String criticality

    private static final List<Class<? extends Vuln>> vulnClasses = [ReflectedXss, BadConfigVuln, BadEncodingVuln,
                                                                    OpenRedirect, RemoteCodeExecution, SqlInjection,
                                                                    PathTraversal, XmlExternalEntitiesAttack, HardcodedCredentials,
                                                                    HardcodedAdminToken, DangerousCookie, MassAssignment,
                                                                    WeakCryptoVuln, DefaultUrlMappings,
                                                                    ]
    private static final log = LogFactory.getLog(this)

    Vuln(String filePath, int lineNumber, String code){
        this.filePath = filePath
        this.lineNumber = lineNumber
        this.code = code
    }

    static final List<Class<? extends Vuln>> getSubclasses() { return vulnClasses }

    void toLog() {
        log.info("title": this.getClass().getSimpleName() + " found", "line number": this.getLineNumber(),
                "cause": this.getReason(), code: this.getCode(), "solution": this.getSolution())
    }

    /**
     * Returns the relative path of the files in the temp folder, where
     * files being analyzed are. It needs their absolute file path.
     */
    private static String getRelativePathOfFileInTemp(String filePath) {
        List<String> tokenizedFilePath = filePath.tokenize('/')
        Integer tempPosition = tokenizedFilePath.findIndexOf { it == 'repositories' }
        return '/' + tokenizedFilePath[tempPosition+1..-1].join('/')
    }


    HashMap<String, HashMap<String, String>> toMap() {
        return ['type': this.isVuln ? 'vulnerability' : 'badPractice',
                'attributes': [
                        'problemName': this.getFriendlyName(),
                        'filePath': getRelativePathOfFileInTemp(this.getFilePath()),
                        'code': this.getCode(),
                        'lineNumber': this.getLineNumber(),
                        'confidence': this.getConfidence(),
                        'information': this.getInformation(),
                        'severity': this.getCriticality(),
                ]
        ]
    }
}
