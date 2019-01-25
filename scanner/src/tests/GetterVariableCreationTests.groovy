import afip.variables.CollectionVariable
import afip.vulns.ReflectedXss

class GetterVariableCreationTests extends BaseIntegrationTest {

    def "should see getter"() {
        when:
            def code = """
            class MainClass {
                def getSomething() {
                    return 'something'
                }
            }
            """
            visitAndCreateAndDetectFromClass(code)
        then:
            classScope.getClassScope().hasDeclaredVariable('something')
    }

    def "should detect getter is tainted"() {
        when:
            def code = """
                class MainClass {
                    def getSomething() {
                        return params.danger
                    }
                    
                    def something_else() {
                        render(model: something)
                    }
                }
                """
            def vuln = visitAndCreateAndDetectFromClass(code)
        then:
            classScope.getMethodOfName("getSomething").isSourceOf(ReflectedXss)
        classScope.getVariableOfName("something").canTrigger(ReflectedXss)
        classScope.getMethodOfName("something_else").getVariableOfName("render").getEntry("model").canTrigger(ReflectedXss)
            classScope.getMethodOfName("something_else")
                    .getLastDeclarationOf("render")
                    .canTrigger(ReflectedXss)
    }

    def "should create correctly typed map variable from a getter"() {
        when:
            def code = """
            class MainClass {
                def getSomething() {
                    return ['a': 'map']
                }
            }
             """
            visitAndCreateAndDetectFromClass(code)
        then:
            classScope.getLastDeclarationOf('something') instanceof CollectionVariable
    }
}

