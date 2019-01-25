import afip.variables.Variable
import afip.vulns.Vuln

class ReturnVariableTests extends BaseIntegrationTest {

    def "Return variable should be defined"() {
            when:
                def code = """
                         class Test{
                            String returner(String a) {
                                return a
                            }
                         }
                    """
                visitAndCreateAndDetectFromClass(code)
            then:
            def returner = classScope.getMethodOfName("returner")
            Variable var
            shouldNotRaiseException({var = returner.getLastDeclarationOf("return")})
            var.getValue().getText() == "a"
    }

    def "Multiples definitions of Return variable should be defined"() {
            when:
                def code = """
                         class Test{
                            String returner(String a) {
                                def b = 'hola'
                                if (true){
                                    return a
                                }else{
                                    return b.foo() + a
                                }
                            }
                         }
                    """
                visitAndCreateAndDetectFromClass(code)
            then:
            def returner = classScope.getMethodOfName("returner")
            Variable var
            shouldNotRaiseException({var = returner.getLastDeclarationOf("return")})
            def definitions = var.getAllLivingDefinitions()
            definitions.size() == 2
            definitions[1].getValue().getText() == "(b.foo() + a)"
    }

    def "return variable properly tainted"() {
            when:
                def code = """
                         class Test{
                            String returner(String a) {
                                def b = 'hola'
                                if (true){
                                    return a
                                }else{
                                    return b.foo() + a
                                }
                            }
                         }
                    """
                visitAndCreateAndDetectFromClass(code)
            then:
            def returner = classScope.getMethodOfName("returner")
            Variable var
            shouldNotRaiseException({var = returner.getLastDeclarationOf("return")})
            returner.getCleanerOf().isEmpty()
            returner.getSourceOf().isEmpty()
            returner.getMenaceOf().size() == Vuln.getSubclasses().size()
    }
    def "return variable properly tainted II"() {
            when:
                def code = """
                         class Test{
                            String returner(String a) {
                                return params.url
                            }
                         }
                    """
                visitAndCreateAndDetectFromClass(code)
            then:
            def returner = classScope.getMethodOfName("returner")
            Variable var
            shouldNotRaiseException({var = returner.getLastDeclarationOf("return")})
            returner.getMenaceOf().isEmpty()
            returner.getCleanerOf().isEmpty()
            returner.getSourceOf().size() == Vuln.getSubclasses().size()
    }
    def "return variable properly tainted III"() {
            when:
                def code = """
                         class Test{
                            String returner(String a) {
                                return "hola" 
                            }
                         }
                    """
                visitAndCreateAndDetectFromClass(code)
            then:
            def returner = classScope.getMethodOfName("returner")
            Variable var
            shouldNotRaiseException({var = returner.getLastDeclarationOf("return")})
            returner.getMenaceOf().isEmpty()
            returner.getSourceOf().isEmpty()
            returner.getCleanerOf().size() == Vuln.getSubclasses().size()
    }
}
