import afip.files.Repository

class RepositoryTests extends BaseTest {
    static File mockRepository
    static File mockGrailsFolder
    static File mockControllerFolder
    static ArrayList<File> mockControllers

    def setupSpec() {
        mockRepository = new File("src/tests/fakeRepository/fury_some_repo")
        mockGrailsFolder = new File(mockRepository, "grails-app")
        mockControllerFolder = new File(mockGrailsFolder, "controllers")
        mockControllers = [
                new File(mockControllerFolder, "TestController.groovy"),
                new File(mockControllerFolder, "ValidController.groovy"),
                new File(mockControllerFolder, "ValidController2.groovy"),
        ]
    }

    def "should find grails app"() {
        when:
            def repository = new Repository(mockRepository, "someID")
        then:
            repository.isGrails()
    }

    def "should find controller folder"() {
        when:
            def repository = new Repository(mockRepository, "someID")
        then:
            repository.getControllers().get(0).getParentFile() == mockControllerFolder
    }

    def "should find valid controller inside controller folder, not the test one"() {
        when:
            def repository = new Repository(mockRepository, "someID")
        then:
        (repository.getControllers() == [mockControllers[2],mockControllers[1]]) || (repository.getControllers() == [mockControllers[1],mockControllers[2]])
    }

}
