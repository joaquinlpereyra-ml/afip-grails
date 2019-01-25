import afip.detectors.HardcodedAdminTokenDetector

class HardcodedAdminTokenTests extends BaseIntegrationTest {
    def setupSpec() {
        detectorManager.turnOn(HardcodedAdminTokenDetector)
     }

    def "should detect hardcoded admin token"(){
        when:
        def code = """
            def something = "ADM-123_231_test"
            """
        def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
        vulns.size() == 1
    }
    def "should not detect hardcoded admin token because they always starts with ADM"() {
        when:
            def code = """
            def something = "123-ADM-123_231_test"
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
            vulns.size() == 0
    }
}
