import afip.detectors.SqlInjectionDetector
import afip.vulns.SqlInjection

class SqlInjectionTests extends BaseIntegrationTest {
    def setupSpec() {
        detectorManager.turnOn(SqlInjectionDetector)
     }

    def "should detect simple sql injection"() {
        when:
            def code = """
                test.find("SELECT" + params.something)
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf("find").canTrigger(SqlInjection)
            vulns.get(0) instanceof SqlInjection
    }

    def "should not detect execute on http"() {
        when:
            def code = """
                        http.execute("https://" + params.something)
                """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf("execute").canTrigger(SqlInjection)
            vulns.isEmpty()
    }

    def "should not detect find on service"() {
        when:
        def code = """
                        fixService.find("https://" + params.something)
                """
        def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
        method.getLastDeclarationOf("find").canTrigger(SqlInjection)
        vulns.isEmpty()
    }

    def "should detect execute on sql"() {
        when:
        def code = """
                        def ds = new BasicDataSource(driverClassName: "org.hsqldb.jdbcDriver",
                            url: 'jdbc:hsqldb:mem:yourDB', username: 'sa', password: '')
                        def sql = new Sql(ds)
                        sql.execute("https://" + params.something)
                """
        def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
        method.getLastDeclarationOf("execute").canTrigger(SqlInjection)
        vulns.size() == 1
        vulns.get(0) instanceof SqlInjection
    }
}