package afip.main

import afip.files.Repository
import org.apache.log4j.BasicConfigurator
import spock.lang.Specification

class RepositoryScannerTest extends Specification {
    static File mockRepository
    static File mockGrailsFolder
    static File mockControllerFolder
    static ArrayList<File> mockControllers

    def setupSpec() {
        BasicConfigurator.configure()
        mockRepository = new File("src/tests/fakeRepository/fury_some_repo")
        mockGrailsFolder = new File(mockRepository, "grails-app")
        mockControllerFolder = new File(mockGrailsFolder, "controllers")
        mockControllers = [
                new File(mockControllerFolder, "TestController.groovy"),
                new File(mockControllerFolder, "ValidController.groovy"),
        ]
    }

    def "should find grails app"() {
        when:
            def repository = new Repository(mockRepository, "someID")
            RepositoryScanner repositoryScanner = new RepositoryScanner()
        then:

            repositoryScanner.scanRepository(repository)
    }
}
