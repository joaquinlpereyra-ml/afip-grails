import afip.detectors.ReflectedXSSDetector
import afip.variables.Variable
import afip.vulns.ReflectedXss

class ReflectedXssTests extends BaseIntegrationTest {
    def setupSpec() {
        detectorManager.setViewsFolder(new File("src/tests/fakeViewsFolder/"))
        detectorManager.turnOn(ReflectedXSSDetector)
    }

    def cleanupSpec() {
        detectorManager.turnOff(ReflectedXSSDetector)
    }

    def "should not detect anything when not in a controller"() {
        when:
            detectorManager.setFilePath("someService.grovy")
            def code = """
                render(model: [parameter: params.danger])
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.size() == 0
    }

    def "should detect dangerous render when model is defined inline"() {
        when:
            def code = """
            render(model: [parameter: params.danger])
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('render').canTrigger(ReflectedXss)
    }

    def "should detect dangerous render when model is another dangerous variable"() {
        when:
            def code = """
               def danger = [parameter: params.danger]
               render(model: danger)
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('render').canTrigger(ReflectedXss)
    }

    def "should detect dangerous render when not all branches have been cleared"() {
        when:
            def code = """
                def danger = [parameter: params.danger]
                if (something) {
                    danger = [parameter: 'not dangerous']
                }
                // but danger is still dangerous, what if something did not happen???
                render(model: danger)
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('render').canTrigger(ReflectedXss)
    }

    def "should not warn when danger variables has been cleared on all branches"() {
        when:
            def code = """
                def danger = [parameter: params.danger]
                if (something) {
                    danger = 'not dangerous'
                } else {
                    danger = 'really it is not dangerous'
                }
                render(model: danger)
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            Variable var = method.getLastDeclarationOf('danger')
            ! (method.getLastDeclarationOf('render').canTrigger(ReflectedXss))
    }

    def "should not warn when danger variables has been cleared on all branches with a swtich statement"() {
        when:
            def code = """
                def danger = [parameter: params.danger]
                switch(something) {
                    case 0:
                        danger = [parameter: 'not dangerous']
                        break
                    case 1:
                        danger = [parameter: 'also not dangerous']
                        break
                    case 2:
                        danger = [parameter: 'dangerous... not']
                        break
                    default:
                        danger = [parameter: 'dangerous... not']
                        break
                }
                render(model: danger)
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            ! (method.getLastDeclarationOf('render').canTrigger(ReflectedXss))
    }

    def "should warn when danger variable has not been cleared on all switch cases"() {
        when:
            def code = """
                def danger = [parameter: params.danger]
                switch(something) {
                    case 0:
                        danger = [parameter: 'not dangerous']
                        break
                    case 1:
                        danger = [parameter: params.another_danger]
                        break
                }
                render(model: danger)
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('render').canTrigger(ReflectedXss)
    }


    def "should warn when using a dangerous default statement, even if everything else has been cleared"() {
        when:
            def code = """
                def danger = [parameter: params.danger]
                switch(something) {
                    case 0:
                        danger = [parameter: 'not dangerous']
                        break
                    case 1:
                        danger = [parameter: 'also not dangerous']
                        break
                    default:
                        danger = [parameter: params.danger]
                        break
                }
                render(model: danger)
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('render').canTrigger(ReflectedXss)
    }


    def "should warn when using a dangerous variable has not been cleared on all with default"() {
        when:
            def code = """
                def danger = [parameter: params.danger]
                switch(something) {
                    case 0:
                        danger = [parameter: 'not dangerous']
                        break
                    case 1:
                        danger = [parameter: params.danger]
                        break
                    default:
                        danger = [parameter: 'not dangerous']
                        break
                }
                render(model: danger)
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('render').canTrigger(ReflectedXss)

    }


    def "should warn of cross site when defining a variable to another dangerous variable"() {
        when:
            def code = """
                def danger = [parameter: params.danger]
                def model = [something: 'safe']
                model = danger
                render(model: model)
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('render').canTrigger(ReflectedXss)
    }


    def "should warn of cross site when defining a variable to another dangerous variable which has been untainted once"() {
        when:
            def code = """
                def danger = [parameter: params.danger]
                if (smt) {
                    danger = [parameter: 'safe']
                }
                def model = danger
                render(model: model)
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('render').canTrigger(ReflectedXss)
    }


    def "should warn of cross site and also find it in the gsp when danger is inline in render"() {
        when:
            def code = """
                render(model: ['vulnerable': params.go], view: 'fakeView1.gsp')
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('render').canTrigger(ReflectedXss)
    }

    def "should not warn of cross site when params is not used in view"() {
        when:
        def code = """
                render(view: 'fakeView1.gsp')
            """
        def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
        vulns.size() == 0
    }

    def "should warn of cross site when params is used in view"() {
        when:
        def code = """
                render(view: 'fakeViewWithParams.gsp')
            """
        def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
        vulns.size() != 0
    }

    def "should detect crossite on dangerously formatted string"() {
        when:
            def code = """
                render (status:404, text:"payment not found \${params?.collectionId}")
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('render').canTrigger(ReflectedXss)
    }

    def "should not detect cross site when using safe content types"() {
        when:
            def code = """
                render(contentType: 'application/json', text: params.go)
                render(contentType: 'application/javascript', text: params.other_go)
            """
            def vulns = visitAndCreateAndDetectFromMethod(code)
        then:
            vulns.isEmpty()
    }

    def "should not warn of cross site when redefining to a non tainted variable"() {
        when:
            def code = """
                def a = params.b
                a = 'hola'
                render(text: a)
            """
                visitAndCreateAndDetectFromMethod(code)
        then:
            !method.getLastDeclarationOf('render').canTrigger(ReflectedXss)
    }

    def "should not detect when encoded as html"() {
        when:
            def code = """
                def a = params.b
                a = a.encodedAsHTML()
                render(text: a)
            """
                visitAndCreateAndDetectFromMethod(code)
        then:
            !method.getLastDeclarationOf('a').canTrigger(ReflectedXss)
            !method.getLastDeclarationOf('render').canTrigger(ReflectedXss)
    }
}