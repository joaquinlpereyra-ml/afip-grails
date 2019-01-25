package afip.main

import afip.code.lines.LineClassifier
import afip.detectors.*
import afip.errors.CantFindRef
import afip.errors.NotAGrailsRepository
import afip.errors.NotValidRepository
import afip.errors.WrongArguments
import afip.files.Repository
import afip.managers.DetectorManager
import afip.scopes.Config
import afip.scopes.Controller
import afip.scopes.Project
import afip.scopes.Service
import afip.utils.Create
import afip.vulns.BadConfigVuln
import afip.vulns.Vuln
import afip.vulns.VulnCollection
import org.apache.commons.logging.LogFactory
/**
 * Main scanner class. It can set up the scan, and has the ability to start one .
 * An abstract class, it has a factory method two create either a RepositoryScanner or a SnippetScanner.
 */
abstract class Scanner {
    DetectorManager detectorManager
    protected String scanHash
    protected static final log = LogFactory.getLog(this)
    Project project
    /**
     * Repository scanners implement a scan(String repoURL, ArrayList<String> tags) method
     * @param detectors: the detectors you want activated for the scan
     * @param scanID: an ID to identify the scan, should be provided and it will then be returned to you
     * @return a RepositoryScanner
     */
    static RepositoryScanner NewRepositoryScanner(String scanID) {
        Scanner scanner = new RepositoryScanner()
        scanner.setScanID(scanID)
        return scanner
    }

    /**
     * Repository scanners implement a scan(String snippet) method
     * @param detectors: the detectors you want activated for the scan
     * @param scanID: an ID to identify the scan, should be provided and it will then be returned to you
     * @return an SnippetScanner
     */
    static SnippetScanner NewSnippetScanner(String snippet, ArrayList<String> detectors, String scanID) {
        Scanner scanner = new SnippetScanner(snippet, detectors)
        scanner.setScanID(scanID)
        return scanner
    }

    /** Set the scanID */
    protected void setScanID(String id) {
        this.scanHash = id
    }

    /**
     * Analyze a Controller.
     * @return an array list of the vulnerabilities found
     */
    protected ArrayList<Vuln> analyze(Controller controller) {
        def analyzer = new MethodAnalyzer(getProject(),getDetectorManager())
        def vulns = []
        for (def method : controller.getMethods()){
            vulns.addAll(analyzer.findVulns(method))
        }
        vulns
    }
}

/**
 * Analyzes a repository, of course.
 */
class RepositoryScanner extends Scanner {
    protected Repository repository

    protected RepositoryScanner() {
        detectorManager = new DetectorManager()
    }

    /**
     * Will scan a repository.
     * @param repositoryURL: the url of the repository
     * @param tags: the tags of the repository you wish to scan
     * @return a VulnCollection
     * @throws NotValidRepository if the repositoryURL does not start with "https://github.com/mercadolbre/" or
     *         if it cant find the basic Grails folders on the repository
     */
    VulnCollection scan(String repositoryURL, List<String> tags) throws NotValidRepository {
        if (!repositoryURL.startsWith("https://github.com/")) {
            throw new NotValidRepository()
        }

        repository = new Repository(repositoryURL, tags, scanHash)
        if (!repository.isGrails()) {
            throw new NotAGrailsRepository()
        }

        VulnCollection vulns = new VulnCollection()
        for (tag in tags) {
            detectorManager.turnOnDetectors()
            try {
                repository.changeTag(tag)
            } catch (CantFindRef e) {
                log.debug(['title': 'cant find tag', 'tag': tag, 'scanHash': scanHash, 'error': e])
                continue
            }
            this.project = new Project(repository)
            detectorManager.setProject(getProject())
            ArrayList<Vuln> tagVulns = analyzeRepo()
            vulns.addTag(tag, tagVulns)
        }
        return vulns
    }

    /**
     * Will scan a tag-less repository. Used mostly for tests.
     */
    ArrayList<Vuln> scanRepository(Repository repository) throws NotAGrailsRepository {
        this.repository = repository
        if (!repository.isGrails()) {
            throw new NotAGrailsRepository()
        }

        this.project = new Project(repository)
        detectorManager.setProject(getProject())
        return analyzeRepo()
    }

    /**
     * Centralizes the scan. Will trigger the smaller analyzeMethod functions.
     */
    private ArrayList<Vuln> analyzeRepo() throws NotAGrailsRepository {
        detectorManager.setFilePath(repository.getConfig().getAbsolutePath())
        detectorManager.setViewsFolder(repository.getViewsFolder())
        detectorManager.setViewFiles(repository.getViews())
        log.debug("title": "starting scan", "scanHash": scanHash)
        ArrayList<Vuln> lilCodeVulns = analyzeLilCodes()
        ArrayList<Vuln> configVulns = analyzeConfig()
        if (configVulns.findAll { it instanceof BadConfigVuln }.size() == 0 ) {
            detectorManager.turnOff(ReflectedXSSDetector)
        }
        ArrayList<Vuln> badEncondingVulns = analyzeBadEncodes()
        ArrayList<Vuln> classicVulns = analyzeControllers()
        return configVulns + badEncondingVulns + lilCodeVulns + classicVulns
    }

    /** Analyzes the controllers */
    private ArrayList<Vuln> analyzeControllers() {
        ArrayList<Vuln> vulns = []
        for (Controller controller : project.getControllers()) {
            log.debug("title": "analzing file", "file": controller.getPath())
            detectorManager.setFilePath(controller.getPath())
            ArrayList<Vuln> controllerVulns = analyze(controller)
            vulns.addAll(controllerVulns)
        }
        return vulns
    }

    /**
     * Analyzes a string.
     * Pretends the string is a controller.
     * This silly function is useful for analyzing GSP and several
     * other regex-friendly files by the same process we analyze
     * true groovy code.
     */
    private ArrayList<Vuln> analyze(String code) {
        Controller controller = Create.Controller(code)
        analyze(controller)
    }

    /** Analyzes the config files. */
    private ArrayList<Vuln> analyzeConfig() {
        log.debug("title": "analyzing file", "file": repository.getConfig().getPath())
        Config config = getProject().getConfig()
        detectorManager.setFilePath(config.getPath())
        MethodAnalyzer analyzer = new MethodAnalyzer(getProject(), getDetectorManager())
        ArrayList<Vuln> vulns = analyzer.analyzeConfig(config)
        detectorManager.turnOff(BadConfigurationDetector)
        return vulns
    }

    /** Analyzes specifically for the bad encoding vulns. */
    private ArrayList<Vuln> analyzeBadEncodes(){
        BadEncodingDetector badEncodingDetector = detectorManager.getDetector(BadEncodingDetector) as BadEncodingDetector
        ArrayList<Vuln> detectedRaw = badEncodingDetector.findRaw()
        ArrayList<Vuln> detectedBadEncodes = (badEncodingDetector.findBadEncodes())
        detectorManager.turnOff(BadEncodingDetector) // not needed no more
        return detectedRaw + detectedBadEncodes
    }

    /** Analyzes specifically for the lil' codes like weak hashing methodNodes
     *  This was pretty clear in the early afip stages, when we were happy and the life was good.
     *  Now it is not.
     *  I ask for forgiveness.
     */
    private ArrayList<Vuln> analyzeLilCodes(){
        log.debug("title": "analyzing file", "file": repository.getUrlMappings())
        ArrayList<Vuln> vulns = []
        if (repository.getUrlMappings()) {
            detectorManager.setFilePath(repository.getUrlMappings().getAbsolutePath())
            vulns.addAll(analyze(repository.getUrlMappings().getAbsolutePath()))
        }

        if(repository.getDatabaseFile()){
            log.debug("title": "analyzing file", "file": repository.getDatabaseFile())
            detectorManager.setFilePath(project.getDatabaseFile().getPath())
            def analyzer = new MethodAnalyzer(getProject(), detectorManager)
            vulns.addAll(analyzer.analyzeDatabaseFile(project.getDatabaseFile()))
        }
        detectorManager.turnOff(DefaultUrlMappingDetector)
        for (Service service : project.getServices() ) {
            log.debug("title": "analyzing lil codes on service", "file": service.getName())
            detectorManager.setFilePath(service.getPath())
            def analyzer = new MethodAnalyzer(getProject(), detectorManager)
            vulns.addAll(analyzer.analyzeService(service))
        }
        return  vulns
    }
}

/**
 * Analyzes a snippet, of course.
 */
class SnippetScanner extends Scanner {
    private String code
    private String vulnName
    private LineClassifier lineClassifier
    private Controller controller

    /**
     * Create a snippet scanner.
     * Snippets can only be analyzed for a single vulnerability!
     */
    protected SnippetScanner(String snippet, ArrayList<String> detectors) {
        if (detectors.size() != 1) {
            throw new WrongArguments()
        }
        // fake a project, pretend the snippet is a controller, be happy
        this.project = Create.MockProject()
        controller = Create.Controller(snippet)
        this.code = snippet
        this.vulnName = detectors.first()
        detectorManager = new DetectorManager(detectors)
        detectorManager.setProject(project)
        detectorManager.activateSnippetMode()
        this.lineClassifier = new LineClassifier(snippet,vulnName)
    }

    /**
     * Scan a simple snippet.
     * @param snippet: a string with valid Groovy code.
     * @return a VulnCollection with the vulns found.
     */
    HashMap<String, ArrayList<Integer>> scan() {
        MethodAnalyzer analyzer = new MethodAnalyzer(getProject(), getDetectorManager())
        for (def method : controller.getMethods()){
            analyzer.playgroundAnalysis(lineClassifier,method)
        }
        lineClassifier.getResult()
    }
}
