package afip.scopes

import afip.files.Repository
import org.apache.log4j.BasicConfigurator
import spock.lang.Specification

class ProjectTests extends Specification{
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
                new File(mockControllerFolder, "ValidController2.groovy"),
        ]
    }

    def "Should create project correctly"(){
        def repository = new Repository(mockRepository, "someID")
        when:
            def project = new Project(repository)
        then:
            project.getConfig()
            project.getControllers().size() == 2
            project.getServices().size() == 1
            project.hasControlllerOfName("ValidController")
            project.hasControlllerOfName("ValidController2")
            project.hasServiceOfName("ValidService")

    }
}
