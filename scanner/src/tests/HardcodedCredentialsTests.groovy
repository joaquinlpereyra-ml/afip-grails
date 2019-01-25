import afip.detectors.HardcodedCredentialsDetector

class HardcodedCredentialsTests extends BaseIntegrationTest {
    def setupSpec() {
        detectorManager.turnOn(HardcodedCredentialsDetector)
     }

    def "should detect hardcoded passwords in Datasource.groovy file"(){
        when:
            detectorManager.getDetector(HardcodedCredentialsDetector).setFilePath("DataSource.groovy")
            def code = """
            var password = "asd123.ka"
            var pwd = "test.123"
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
            vulns.size() == 2
    }

    def "should detect hardcoded passwords in Config.groovy file"(){
        when:
            detectorManager.getDetector(HardcodedCredentialsDetector).setFilePath("DataSource.groovy")
            def code = """
                var password = "asd123.ka"
                var pwd = "test.123"
                """
            def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
            vulns.size() == 2
    }

    def "should not detect passwords in other files yet, because we don't have a passwords api solution"(){
        when:
            detectorManager.getDetector(HardcodedCredentialsDetector).setFilePath("AnotherFile.groovy")
            def code = """
                    var password = "asd123.ka"
                    var pwd = "test.123"
                    """
            def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
            vulns.size() == 0
    }

    def "should not detect Fury Utils Env as a hardcoded password"(){
        when:
            detectorManager.getDetector(HardcodedCredentialsDetector).setFilePath("AnotherFile.groovy")
            def code = """
                password = FuryUtils.getEnv('DB_MYSQL_ADDRESSESTEST_ZIPMANLOG_ZIPMANLOG_WPROD')
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
            vulns.size() == 0
    }

    def "should detect this"(){
        when:
            detectorManager.getDetector(HardcodedCredentialsDetector).setFilePath("DataSource.groovy")
            def code = """
                var test= "asd123.ka"
                var pwd = test
            """

            def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
            vulns.size() == 1
    }
    def "should not detect this"(){
        when:
            detectorManager.getDetector(HardcodedCredentialsDetector).setFilePath("DataSource.groovy")
            def code = """
                var pwd = "DB_SARADASA"
            """

            def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
            vulns.size() == 0
    }

    def "should not detect this either"(){
        when:
            detectorManager.getDetector(HardcodedCredentialsDetector).setFilePath("DataSource.groovy")
            def code = """
                var pwd_end = "soyUnaVariableDeEntorno"
            """

            def vulns = visitAndCreateAndDetectFromMethod(code)

        then:
            vulns.size() == 1
    }

}

