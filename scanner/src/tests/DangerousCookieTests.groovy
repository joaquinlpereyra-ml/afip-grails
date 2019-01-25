import afip.detectors.DangerousCookieDetector

class DangerousCookieTests extends BaseIntegrationTest {
    def setupSpec() {
        detectorManager.turnOn(DangerousCookieDetector)
     }

    def "should detect cookie orgid as dangerous"() {
        when:
            def code = """
                def cook = cookies.get("orgid")
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
            vulns.size() == 1
    }

    def "should detect cookie orgapi as dangerous"() {
        when:
            def code = """
                def cook = cookies.get("orgapi")
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
        vulns.size() == 1
    }
}