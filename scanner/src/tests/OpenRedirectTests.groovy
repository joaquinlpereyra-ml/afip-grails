import afip.detectors.OpenRedirectDetector
import afip.main.MethodAnalyzer
import afip.utils.Create
import afip.variables.Variable
import afip.vulns.OpenRedirect

class OpenRedirectTests extends BaseIntegrationTest {
    def setupSpec() {
        detectorManager.turnOn(OpenRedirectDetector)
     }

    def "should detect the most obvious case of open redirect"() {
        when:
            def code = """
                redirect(url: params.url)
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf("redirect").canTrigger(OpenRedirect)
    }

    def "should detect slightly less obvious case of open redirect"() {
        when:
            def code = """
                def a = params.url
                redirect(url: a)
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf("redirect").canTrigger(OpenRedirect)
    }

    def "foo"() {
        when:
        def code = """
                class Test {
                    def clean(foo) { 
                        return isValidURL(foo) 
                    }
                    def someController() {
                        def text = clean(params.url)
                        redirect(url: text)
                    } 
                }
            """
        def results = visitAndCreateAndDetectFromClass(code)
        then:
        classScope.getMethodOfName("clean").isCleanerOf(OpenRedirect)
        Variable var = classScope.getLastDeclarationOf("text")
        !(var.canTrigger(OpenRedirect))
        results.isEmpty()
    }

    def "should not detect open redirect if using sitesec's security context holder"() {
        when:
            def code = """
                if (form.login.toBoolean() && userId == -1) {
                    userId = securityContextHolder.getNotAuthorizedUserId(request)
                    if (userId == -1) {
                        redirect(url: securityContextHolder.getLoginURL(request))
                        return
                    }
                    // Solo dejo pasar a los notAuthenticated pero que estan deactive, el resto se deberia loguear.
                    def userStatus = apiCallsService.getUserStatus(userId)
                    if (userStatus != "deactive") {
                        redirect(url: securityContextHolder.getLoginURL(request))
                        return
                    }
                }
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            !vulns.contains(OpenRedirect)
    }

    def "should not detect if input passed through safety function"() {
        when:
            def code = """
                class Test {
                    def method(){
                        def text = params.url
                        text = isValidURL(text)
                        redirect(url: text)
                    }
                }
            """
            def mock = Create.MockProject()
            def clazz = Create.ClassScope(code)
            def ma = new MethodAnalyzer(mock,detectorManager)
            def method = clazz.getMethodOfName("method")
            def vulns = ma.findVulns(method)
        then:
            vulns.isEmpty()
    }

    def "should not detect without url, even when it sees it as tainted"() {
        when:
            def code = """
                def text = params.url
                redirect(text)
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf("redirect").canTrigger(OpenRedirect)
            vulns.isEmpty()
    }

    def "should not detect if url coming from config"() {
        when:
            def code = """
                    redirect( uri: \$grailsApplication.config.app.urls.home.mp[request.user.site_id.toLowerCase()]/activities )
                """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            method.getVariableOfName("redirect").canTrigger(OpenRedirect)
            vulns.isEmpty()
    }

    def "weird open redirect"() {
        when:
            def code = """
                def index(){
                    if (!request.mobile){
                        redirect(uri:"/settings/account\${request.queryString ? '?' + request.queryString : ''}")
                        return;
                    }

                    redirect(uri:"/settings/nav")
                }
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.isEmpty()
     }
    def "goo"() {
        when:
        def code = """
                class Test {
                    def goo(){
                        def bar = params.algo
                        if (sara){
                            bar = isValidURL(bar)
                        }
                        else {
                            bar = params.wololo
                        }
                        redirect(url: bar)
                   }
                }
            """
        def results = visitAndCreateAndDetectFromClass(code)
        then:
        def method = classScope.getMethodOfName("goo")
        Variable var = method.getLastDeclarationOf("bar")
        var.canTrigger(OpenRedirect)
        !results.isEmpty()
    }

    def "should see vulnerability"() {
        when:
        def code = """
            class Goo {
              def makeValidURL(url) {
              if (isValidURL(url)) {
                return url
              }
              return "https://mercadolibre.com"
            }

            def buyController() {
              def url
              if (params.buySuccessful) {
                url = params.redirectURL
                url = makeValidURL(url)
              } else {
                url = params.failURL
              }
              redirect(url: url)
              }
           }
            """
        def results = visitAndCreateAndDetectFromClass(code)
        then:
        def method = classScope.getMethodOfName("buyController")
        Variable var = method.getLastDeclarationOf("url")
        var.canTrigger(OpenRedirect)
        !results.isEmpty()
    }
}
