package afip.main

import afip.files.Repository
import afip.managers.DetectorManager
import afip.scopes.Project
import afip.vulns.PathTraversal
import afip.vulns.ReflectedXss
import org.apache.log4j.BasicConfigurator
import spock.lang.Specification

class MethodAnalyzerTest extends Specification {
    static File mockRepository
    static File mockGrailsFolder
    static File mockControllerFolder
    static ArrayList<File> mockControllers
    static Project project
    static DetectorManager dm
    static MethodAnalyzer ma
    static Repository repository

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
        repository = new Repository(mockRepository, "someID")
        project = new Project(repository)
        dm = new DetectorManager()
        ma = new MethodAnalyzer(project, dm)
        dm.setFilePath(repository.getConfig().getAbsolutePath())
        dm.setProject(project)
    }

    def "works as desired"() {
        when:
        def controller = project.getControllerOfName("ValidController")
        def vulns = ma.findVulns(controller.getMethodOfName("notMethod"))
        then:
        def s = project.getServiceOfName("ValidService")
        def method = s.getMethodOfName("cleaner")
        def controllerMethod = project.getControllerOfName("ValidController").getMethodOfName("notMethod")
        method.isCleanerOf(PathTraversal)
        !controllerMethod.isSinkOf(PathTraversal)
        vulns.isEmpty()
    }

    def "function not found work as menace"() {
        when:
        def controller = project.getControllerOfName("ValidController2")
        def vulns = ma.findVulns(controller.getMethodOfName("notMethod"))
        then:
        def controllerMethod = project.getControllerOfName("ValidController2").getMethodOfName("notMethod")
        controllerMethod.isSinkOf(PathTraversal)
        vulns.size() == 1
        vulns.first().getClass() == PathTraversal
    }

    def "should found vuln"() {
        when:
        dm.setFilePath(project.getControllerOfName("ValidController").getPath())
        def controller = project.getControllerOfName("ValidController")
        def vulns = ma.findVulns(controller.getMethodOfName("vulnerable"))
        then:
        def source = project.getServiceOfName("ValidService").getMethodOfName("source")
        source.isSourceOf(ReflectedXss)
        controller.getMethodOfName("vulnerable").getLastDeclarationOf("a").canTrigger(ReflectedXss)
        !vulns.isEmpty()
        vulns.first().getClass() == ReflectedXss
    }
}
