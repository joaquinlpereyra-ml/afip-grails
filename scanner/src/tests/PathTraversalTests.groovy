import afip.detectors.PathTraversalDetector
import afip.vulns.PathTraversal

class PathTraversalTests extends BaseIntegrationTest {
    def setupSpec() {
        detectorManager.turnOn(PathTraversalDetector)
     }

    def "should detect the most obvious case of path traversal"() {
        when:
        def code = """
               def f = new File(params.file)
               def f2 = f.Write()
            """
        def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
        !vulns.isEmpty()
    }

    def "should detect a slightly more complicated case of path traversal"() {
        when:
            def code = """
                def filePath = params.file
                def file = new File(filePath)
                def f2 = file.Read()
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.size() == 1
    }

    def "should not detect path traversal"() {
        when:
            def code = """
                def filePath = params.file
                def paco = new File(filePath)
                def unpaco= cucu.isValidPath(paco) 
                def f2 = unpaco.Read()
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.size() == 0
    }

    def "should not detect path traversal II"() {
        when:
            def code = """
                def filePath = params.file
                def paco = new File(filePath)
                def unpaco= isValidPath(paco) 
                def f2 = unpaco.Read()
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.size() == 0
    }

    def "should not detect path traversal III"() {
        when:
            def code = """
                class Test {
                     def method(){
                            def filePath = params.foo
                            if(!isValidPath(filePath)){ 
                                throw new BadRequestException("Invalid file path");
                            }
                            def file = new File(filePath)
                            file.size()
                     }
                     
                     def isValidPath(){
                        return false
                     }
                }
            """
            def vulns = visitAndCreateAndDetectFromClass(code)
        then:
            !classScope.getLastDeclarationOf("filePath").canTrigger(PathTraversal)
            vulns.size() == 0
    }
}