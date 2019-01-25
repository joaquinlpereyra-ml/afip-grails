import afip.detectors.RemoteCodeExecutionDetector
import afip.vulns.RemoteCodeExecution
import org.codehaus.groovy.runtime.typehandling.GroovyCastException

class RemoteCodeExecutionTests extends BaseIntegrationTest {
    def setupSpec() {
        detectorManager.turnOn(RemoteCodeExecutionDetector)
     }

    def "should detect the most obvious case of rce"() {
        when:
            def code = """
                params.command.execute()
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            !(vulns.isEmpty())
            vulns.get(0) instanceof RemoteCodeExecution
    }

    def "should detect the not so obvious case of rce"() {
        when:
            def code = """
                def command =  params.command
                if (something) {
                    command = 'ls'
                }
                command.execute()
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf("execute").canTrigger(RemoteCodeExecution)
            vulns && vulns.get(0) instanceof RemoteCodeExecution
    }

    def "should detect a process builder creation"() {
        when:
            def code = """
                def process = new ProcessBuilder(params.code).start()
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf("ProcessBuilder").canTrigger(RemoteCodeExecution)
            method.getLastDeclarationOf("process").canTrigger(RemoteCodeExecution)
            vulns.get(0) instanceof RemoteCodeExecution
    }

    def "should not detect remote code execution on other classes names"() {
        when:
            def code = """
                def process = new SomethingWeird(params.code).start()
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            !(method.getLastDeclarationOf("process").canTrigger(RemoteCodeExecution))
    }

    def "should not detect remote code execution" () {
       when:
           def code = """
                BoundRequestBuilder r = prepareGet(path, params, headers); 
                def resp = r.execute().get()             
           """
           def vulns = visitAndCreateAndDetectFromMethod(code)
       then:
           vulns.isEmpty()
    }

    def "should not explode" () {
        setup:
            def code = """
                private def getpages(bigqueryrequest request) {                                                   
                    def response = request.execute();                                                             
                    def wholeresponse = response                                                                  
  
                    while (response.containskey("pagetoken")) {                                                   
                      request = request.set("pagetoken", response.get("pagetoken"));                            
      
                      response = request.execute();                                                             
  
                      wholeresponse.getrows().addall(response.getrows())                                        
                    }
  
                    wholeresponse                                                                                 
                }
            """
        when:
            visitAndCreateAndDetectFromMethod(code)
        then:
            notThrown(GroovyCastException)
    }
    def "should not explode on this type of execute" () {
        when :
        def code = """
            execute("get", null, url, headers, metricName, restClient, callApiName, retryNumber, detailCallApi)
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.isEmpty()
    }

    def "should not detect rce  on http" () {
        when :
        def code = """
                def process = new someHttpRequester(params.code).start()
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.isEmpty()
    }

    def "should not detect rce  on request" () {
        when :
        def code = """
                def process = new someRequester(params.code).start()
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.isEmpty()
    }
}
