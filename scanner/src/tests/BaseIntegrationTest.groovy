import afip.main.MethodAnalyzer
import afip.managers.DetectorManager
import afip.scopes.ClassScope
import afip.scopes.Method
import afip.scopes.Project
import afip.utils.Create

class BaseIntegrationTest extends BaseTest {
    static DetectorManager detectorManager
    static MethodAnalyzer analyzer
    Method method
    ClassScope classScope
    Boolean shouldRaiseException(closure){
        Boolean failed = false
        try {
            closure()
        }
        catch (Exception ignore){
              failed = true
        }
        return failed
    }
    Boolean shouldNotRaiseException(closure){
        !shouldRaiseException(closure)
    }

    def setupSpec() {
        Project mock = new Create().MockProject()
        detectorManager = new DetectorManager()
        detectorManager.activateSnippetMode()
        analyzer = new MethodAnalyzer(mock,detectorManager)
        detectorManager.setProject(mock)
    }

    def setup() {
        detectorManager.setFilePath("someController.groovy")
    }


    def visitAndCreateAndDetectFromMethod(String code) {
        Project mock = Create.MockProject()
        MethodAnalyzer analyzer = new MethodAnalyzer(mock,detectorManager)
        this.method = MethodScope(code)
        return analyzer.findVulns(this.method)
    }

    def visitAndCreateAndDetectFromClass(String code) {
        this.classScope = ClassScope(code)
        def methods = this.classScope.getMethods()
        for (def m : methods){
            analyzer.analyzeMethod(m)
        }
        return analyzer.findVulns(methods[0])
    }
}
