import afip.detectors.WeakCryptoDetector
import afip.files.Repository
import afip.main.RepositoryScanner
import afip.vulns.WeakCryptoVuln

class WeakCryptoTests extends BaseIntegrationTest {
   def setupSpec(){
       detectorManager.turnOn(WeakCryptoDetector)

   }

    def "should find weack crypto on services"() {
        when:
            def mockRepository = new File("src/tests/fakeRepository/fury_some_repo")
            def mockGrailsFolder = new File(mockRepository, "grails-app")
            def mockControllerFolder = new File(mockGrailsFolder, "controllers")
            def mockControllers = [
                    new File(mockControllerFolder, "TestController.groovy"),
                    new File(mockControllerFolder, "ValidController.groovy"),
            ]
            def repository = new Repository(mockRepository, "someID")
        then:
            RepositoryScanner repositoryScanner = new RepositoryScanner()
            def vulns = repositoryScanner.scanRepository(repository)
            println(vulns.collect { it.toMap() })
            vulns.findAll{(it instanceof WeakCryptoVuln) }.size() == 3
    }

    def "the use of a method that contains a weak crypto name is considered dangerous"(){
        when:
            def code = """
            def encryptedVariable = something.encodeAsMD5()
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
            vulns.size() == 1
    }

    def "if the variable name contains the name of a weak crypto is considered dangerous"(){
        when:
            def code = """
                def nameMD5 = this.name
                """
            def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
            vulns.size() == 1
    }

}
