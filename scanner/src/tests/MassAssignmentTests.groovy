import afip.detectors.MassAssignmentDetector
import afip.vulns.MassAssignment

class MassAssignmentTests extends BaseIntegrationTest {
    def setupSpec() {
        detectorManager.turnOn(MassAssignmentDetector)
     }

    def "should detect the the most obvious case of mass assignment"() {
        when:
            def code = """
                sillyConstructor = Class(params)
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.size() == 1 && vulns.get(0) instanceof MassAssignment
    }

    def "should not detect when specifying params"() {
        when:
            def code = """
                sillyConstructor = Class(params.id)
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.size() == 0
    }

    def "should not detect when not a constructor call"() {
        when:
            def code = """
                sillyConstructor = method(params)
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.size() == 0

    }
}