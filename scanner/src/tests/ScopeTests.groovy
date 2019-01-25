class ScopeTests extends BaseIntegrationTest {

    def "Class scope is well defined"() {
            when:
                def code = """
                         class Test{
                            String danger(String a) {
                                render(model: a)
                            }
                         }
                    """
                visitAndCreateAndDetectFromClass(code)
            then:
            classScope.getName() == "Test"
            classScope.hasMethodOfName("danger")
    }
    def "Should not find nonexistent scope"() {
            when:
                def code = """
                         class Test{
                            String danger(String a) {
                                render(model: a)
                            }
                         }
                    """
                visitAndCreateAndDetectFromClass(code)
            then:
                shouldRaiseException({classScope.getMethodOfName("dangeridoo")})
    }
}
