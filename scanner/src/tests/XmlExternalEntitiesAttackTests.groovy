import afip.detectors.XmlExternalEntitiesAttackDetector
import afip.vulns.XmlExternalEntitiesAttack

class XmlExternalEntitiesAttackTests extends BaseIntegrationTest {
    def setupSpec() {
        detectorManager.turnOn(XmlExternalEntitiesAttackDetector)
     }

    def "should detect a vulnerable xml slurper"() {
        when:
            def code = """
                def vulnerable = new XmlSlurper()
                vulnerable.doSomething()
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf("vulnerable").canTrigger(XmlExternalEntitiesAttack)
            vulns.size() == 1
    }

    def "should untaint this slurper"() {
        when:
            def code = """
                def nonXXEVulnerableParser = new XmlSlurper();
                nonXXEVulnerableParser.setFeature("http://xml.org/sax/features/external-general-entities", false)
                def parsedObj = nonXXEVulnerableParser.parseText(xmlWithXXEVulnerability)
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            !method.getLastDeclarationOf("parsedObj").canTrigger(XmlExternalEntitiesAttack)
            vulns.size() == 0
    }

    def "should see an if and that stuff"() {
        when:
            def code = """
                def vulnerableXSSParser = new XmlSlurper();
                if (something) {
                    vulnerableXSSParser.setFeature("http://xml.org/sax/features/external-general-entities", false)
                }
                vulnerableXSSParser.parseText(something)
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf("vulnerableXSSParser").canTrigger(XmlExternalEntitiesAttack)
    }
}