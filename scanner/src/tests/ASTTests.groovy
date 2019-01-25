import afip.errors.VariableNotFound
import afip.variables.CollectionVariable

class ASTTests extends BaseIntegrationTest {

    def "our code visitor should see a render method call when there is return of a map"() {
        when:
            def code = """
                def functionWhichReturnsAMap() {
                    return [IAmActuallyRendering: something]
                }
            """
            def methods = MethodScopes(code)
        then:
            def method = methods.first()
            method.getLastDeclarationOf('render')
    }

    def "should see only one branch when ending if inmediately"() {
        when:
            def code = """
            class Test {
                def foo(bar) {
                    if (isValidURL(bar)) {
                        return bar
                    }
                    return "https://mercadolibre.com"
                }
                
                def wops() {
                    def url = foo(params.url)
                    redirect(url: url)
                }
            }
            """
            def vulns = visitAndCreateAndDetectFromClass(code)
        then:
            vulns.size() == 0
    }


    def "our code visitor should see NOT see a render when not retuning a map"() {
        setup:
            def code = """
                    def functionWhichReturnsAMap() {
                        return 'i am just returning a string'
                    }
                """
            def methods = MethodScopes(code)
            def method = methods.first()
        when:
            method.getLastDeclarationOf('render')
        then:
            VariableNotFound _ = thrown()
    }

    def "we should change the type of a variable when finding new information"() {
        when:
            def code = """
                def something() {
                    def a = some_unknown_method()
                    a << ['some': 'value']
                }
            """
            def methods = MethodScopes(code)
        then:
            def method = methods.first()
            method.getLastDeclarationOf('a') instanceof CollectionVariable
    }

    def "we should create a map when trying to add to it even if we don't really know it"() {
        when:
        def code = """
                def something() {
                    a << ['some': 'value']
                }
            """
            def methods = MethodScopes(code)
        then:
            def method = methods.first()
            method.getLastDeclarationOf("a") instanceof CollectionVariable
    }

    def "it should visit the call to add() without noticing it is an overwritten list-adding method"() {
        setup:
            def code = """
                 def make() {
                     String action = params.method
                     if (action == "add") {
                         add();
                     } else {
                         if( action == "remove" ) {
                              remove();
                         }
                     }
                 }
            """
        when:
            MethodScopes(code)
        then:
            // this is a bad test, really
            notThrown(NullPointerException)
    }
    def "variable named loadFactor should not explode"() {
        setup:
            def code = """
                def sitescache = [
                    concurrencylevel:100,
                    initialcapacity:10000,
                    purgesleep:100,
                    purgeblocksize:100,
                    loadfactor:0.8
      ]
      
        """
        when:
            MethodScopes(code)
        then:
            notThrown(ReadOnlyPropertyException)
    }
}
