import afip.detectors.BadConfigurationDetector
import afip.scopes.ScopePrinter

class BadConfigTests extends BaseIntegrationTest {
    def setupSpec() {
        detectorManager.turnOn(BadConfigurationDetector)
    }

    def setup() {
        detectorManager.setFilePath("Config.groovy")
    }

    def "should see three bad configurations"() {
        when:
            def code = """
                grails.views.default.codec="none"

                // GSP settings
                grails {
                    views {
                        gsp {
                            encoding = 'UTF-8'
                            htmlcodec = 'xml' // use xml escaping instead of HTML4 escaping
                            codecs {
                                expression = 'none' // escapes values inside ${}
                                scriptlet = 'none' // escapes output from scriptlets in GSPs
                                taglib = 'none' // escapes output from taglibs
                                staticparts = 'none' // escapes output from static template parts
                            }
                        }
                        // escapes all not-encoded output at final stage of outputting
                        // filteringCodecForContentType.'text/html' = 'html'
                    }
                }
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.size()==3
    }
}
