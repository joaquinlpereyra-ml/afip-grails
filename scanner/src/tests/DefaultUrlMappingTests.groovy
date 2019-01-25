import afip.detectors.DefaultUrlMappingDetector

class DefaultUrlMappingTests extends BaseIntegrationTest {
   def setupSpec(){
       detectorManager.turnOn(DefaultUrlMappingDetector)
   }

   def "should detect default url mappings"(){
       when:
       detectorManager.getDetector(DefaultUrlMappingDetector).setFilePath("UrlMappings.groovy")
            def code = """
                    static mappings = {
                    "/\$controller/\$action?/\$id?(.\$format)?"{
                        constraints {
                            // apply constraints here
                        }
                    }

                    "/"(view:"/index")
                    "500"(view:'/error')
                    }
            """
           def vulns = visitAndCreateAndDetectFromMethod(code)
       then:
            vulns.size() == 1
   }

    def "should not detect default url mappings"(){
        when:
        detectorManager.getDetector(DefaultUrlMappingDetector).setFilePath("UrlMappings.groovy")
            def code = """
            static mappings = {
            
                "/test/test/\$siteId/test"(controller: "test") {
                action = [POST: "test"]
                }
                
                 "/test/test"(controller: "test") {
                action = [POST: "test"]
                }
                
            }
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.size() == 0
    }

}
