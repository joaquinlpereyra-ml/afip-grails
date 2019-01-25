package afip.managers

import afip.detectors.*
import afip.scopes.Project
import afip.variables.Variable
import afip.vulns.Vuln
/**
 * The DetectorManager is a class which manages all the afip.detectors found in the program for easier
 * interaction with them.
 *
 * IMPORTANT: Before usage, you MUST CALL setFilePath, setViewsFolder and setViewFiles.
 *            If you do not this will explode. Everywhere.
 */
class DetectorManager {
    private HashMap<Class<Detector>, Detector> detectors = new HashMap<>()
    private Project project
    private List<Class<? extends Detector>> allDetectors = [ReflectedXSSDetector,
                                                           BadConfigurationDetector,
                                                           BadEncodingDetector,
                                                           DefaultUrlMappingDetector,
                                                           OpenRedirectDetector,
                                                           RemoteCodeExecutionDetector,
                                                           SqlInjectionDetector,
                                                           WeakCryptoDetector,
                                                           PathTraversalDetector,
                                                           HardcodedCredentialsDetector,
                                                           XmlExternalEntitiesAttackDetector,
                                                           HardcodedAdminTokenDetector,
                                                           DangerousCookieDetector,
                                                           MassAssignmentDetector,
                                                           ]

    /**
     * Create an instance of a detector manager
     * with all the detectors turned on
     */
    DetectorManager() {
        setAllDetectors()
        turnOnDetectors()
    }

    /**
     * Create an instance of a detector manager
     * with only the specified detectors turned on
     */
    DetectorManager(ArrayList<String> detectors) {
        setAllDetectors()
        setDetectorsFromStrings(detectors)
    }

    /** Get the cleaners from every active detector. */
    HashMap<Class<? extends Vuln>, HashSet<String>> getKnownCleaners() {
        HashMap<Class<? extends Vuln>, HashSet<String>> cleaners = new HashMap<Class<? extends Vuln>, HashSet<String>>()
        for (Detector detector : getActiveDetectors() ) {
            cleaners.put(detector.getVuln(), detector.getDefaultCleaners())
        }
        return cleaners
    }

    /** Sets the project for every detector */
    void setProject(Project project) {
        this.project = project
        for (Detector detector : getActiveDetectors()) {
            detector.setProject(project)
        }
    }

    /** Prepares the detector to run on snippet mode: no files or folders will be taken into account */
    void activateSnippetMode() {
        new File("snippetModeViewsFolder").mkdirs()
        setFilePath("someController.groovy")
        setViewsFolder(new File("snippetModeViewsFolder"))
        setViewFiles([])
    }

    /** Will translate from the detectors as strings to initialized instances of the specified
     * detectors
     */
    private void setDetectorsFromStrings(ArrayList<String> detectors) {
        LinkedHashMap<String, Class<? extends Detector>> stringToDetector = [
                'Reflected XSS': ReflectedXSSDetector,
                'Default encoding set to None': BadConfigurationDetector,
                'Bad Encoding': BadEncodingDetector,
                'Default mappings': DefaultUrlMappingDetector,
                'Open Redirect': OpenRedirectDetector,
                'Remote code execution': RemoteCodeExecutionDetector,
                'Sql injection': SqlInjectionDetector,
                'Weak Hashing Method': WeakCryptoDetector,
                'Path traversal': PathTraversalDetector,
                'Hardcoded credentials': HardcodedCredentialsDetector,
                'XML external entities attack': XmlExternalEntitiesAttackDetector,
                'Hardcoded admin token': HardcodedAdminTokenDetector,
                'Dangerous cookie': DangerousCookieDetector,
                'Mass Assignment': MassAssignmentDetector,
        ]
        ArrayList<Class<? extends Detector>> detectorClasses = detectors.collect { detector -> stringToDetector.get(detector) }
        detectorClasses.each { detector ->
            this.detectors.get(detector).turnOn()
        }
    }

    /** Return all the possible afip.detectors, active or not */
    HashSet<Class<Detector>> getAllDetectorsClasses() {
        HashSet<Class<Detector>> detectors = new HashSet<>()
        detectors.addAll(allDetectors)
        return detectors
    }

    private void setAllDetectors() {
        for (Class<Detector> detectorClass : getAllDetectorsClasses()) {
            Detector detector = detectorClass.newInstance()
            addDetector(detector)
        }
    }

    void turnOnDetectors() {
        for (Detector detector : detectors.values()) {
            detector.turnOn()
        }
    }


    /** Adds a detector to the collection of active afip.detectors */
    void addDetector(Detector detector) {
        detectors.put(detector.getClass() as Class<Detector>, detector)
    }

    void turnOn(Class<Detector> detector) {
        detectors.get(detector).turnOn()
    }

    /** Returns all afip.detectors */
    ArrayList<Detector> getAllDetectors() {
        return detectors.values()
    }

    /** Returns all active afip.detectors */
    ArrayList<Detector> getActiveDetectors() {
        def res = new ArrayList<Detector>()
        for (Detector detector : detectors.values()) {
           if (detector.isOn()) {
               res.push(detector)
            }
        }
        return res
    }

    /** Returns the active vulnerabilities from
     * the turned on detectors */
    ArrayList<Class<? extends Vuln>> getActiveVulns() {
        return getActiveDetectors().collect { it.getVuln() }
    }

    /** Sets the file path for every afip.detectors */
    void setFilePath(String filePath) {
        for (Detector detector : getAllDetectors()) {
            detector.setFilePath(filePath)
        }
    }

    /** Sets the views folder path for every afip.detectors */
    void setViewsFolder(File viewFolder) {
        for (Detector detector : getAllDetectors()) {
            detector.setViewsFolder(viewFolder)
        }
    }

    /** Sets the views for every afip.detectors */
    void setViewFiles(ArrayList<File> viewFiles) {
        for (Detector detector : getAllDetectors()) {
            detector.setViewFiles(viewFiles)
        }
    }


    /** Removes a detector from the collection of active afip.detectors */
    void turnOff(Class<Detector> detectorClass) {
        detectors.get(detectorClass).turnOff()
    }

    /** Removes all detectors from the collection of active afip.detectors */
    void turnOffDetectors() {
        for (Detector detector : detectors.values()) {
            detector.turnOff()
        }
    }

    /** Return the active instance of the detector of the given class.
     * If the detector of this class is not active, it will return null.
     */
    Detector getDetector(Class<Detector> detector) {
        return detectors.get(detector)
    }

    /** Return the active instance of the detector of the given class.
     * If the detector of this class is not active, it will return null.
     */
    Detector getDetectorOf(Class<Vuln> vuln) {
        return getActiveDetectors().find{ v -> v.getVuln() == vuln }
    }

    /**
     * Runs all the added detectors via the turnOn method
     * on the given expression
     */
    ArrayList<Vuln> detect(Variable var) {
        if (var.getName() == "return") return []
        ArrayList<Vuln> vulnsFound = new ArrayList<>()

        for (Detector detector : getActiveDetectors()) {
            ArrayList<Vuln> vulns = detector.detect(var)
            vulnsFound.addAll(vulns)
        }
        return vulnsFound
    }
}
