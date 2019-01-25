import afip.detectors.ReflectedXSSDetector
import afip.main.MethodAnalyzer
import afip.tainter.MethodTainter
import afip.tainter.ParanoidMethodTainter
import afip.utils.Create
import afip.vulns.ReflectedXss

class ParanoidMethodTainterTests extends BaseIntegrationTest{
    def setupSpec() {
        detectorManager.turnOn(ReflectedXSSDetector)
    }

    def "should find vulns on parameterVariables with paranoidTainter"(){
        when:
            def code = """
                    void func(param1,param2){
                        render(param1)
                    }
                """
            def clazz = Create.ClassScope(code)
            def mock = Create.MockProject()
            def ma = new MethodAnalyzer(mock,detectorManager)
            def pmt = new ParanoidMethodTainter(detectorManager.getActiveVulns(),ma)
            def method = clazz.getMethodOfName("func")
            ma.activeMethod = method
            ma.recursiveTaintAnalysisWith(pmt,[method])
        then:
            method.getLastDeclarationOf("render").canTrigger(ReflectedXss)
            method.getLastDeclarationOf("param1").canTrigger(ReflectedXss)
            method.getLastDeclarationOf("param2").canTrigger(ReflectedXss)
    }



    def "should not find vulns on parameterVariables without paranoidTainter"(){
        when:
            def code = """
                    void func(param1,param2){
                        render(param1)
                    }
                """
            visitAndCreateAndDetectFromClass(code)
        then:
        def method = classScope.getMethodOfName("func")
        !method.getLastDeclarationOf("render").canTrigger(ReflectedXss)
        !method.getLastDeclarationOf("param1").canTrigger(ReflectedXss)
        !method.getLastDeclarationOf("param2").canTrigger(ReflectedXss)
    }
}
