import afip.variables.CollectionVariable

class CollectionTests extends BaseIntegrationTest {

    def "A list is registered as a CollectionVariable"() {
        when:
            def code = """
                    def a = []
                """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('a') instanceof CollectionVariable
    }

    def "A map is registered as a CollectionVariable"() {
        when:
            def code = """
                    def a = [:]
                """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('a') instanceof CollectionVariable
    }

    def "Adding values to a list with arrowOperator"() {
        when:
            def code = """
                    def a = []
                    a << "l"
                """
            visitAndCreateAndDetectFromMethod(code)

        then:
            CollectionVariable var = method.getLastDeclarationOf("a")
            var instanceof CollectionVariable
            var.size() == 1
    }

    def "Adding values to a list with add method"() {
        when:
            def code = """
                    def a = []
                    a.add("Hola")
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            CollectionVariable var = method.getLastDeclarationOf("a")
            var instanceof CollectionVariable
            var.size() == 1
    }

    def "Adding values to a map with arrowOperator"() {
        when:
            def code = """
                    def a = [:]
                    a << ["asd": "hola"]
                """
            visitAndCreateAndDetectFromMethod(code)
        then:
            CollectionVariable var = method.getLastDeclarationOf("a")
            var instanceof CollectionVariable
            var.size() == 1
            var.getEntry('asd')
    }

    def "addings values to a map with put method works"() {
        when:
            def code = """
                def dict = [:]
                dict.put('a', 'b')
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            CollectionVariable var = method.getLastDeclarationOf("dict")
            var instanceof CollectionVariable
            var.size() == 1
            var.getEntry('a')
    }

    def "when using put as an http request it should not be registered as a collection"() {
        when:
            def code = """
                slowSimpleRestClient.put(uri: uri, headers: ["Content-Type": "application/json"],
                    success: { resp.data = it.data
                        resp.status = it.status.getStatusCode()
                    },
                    failure: {  
                        resp.data = it.data
                        resp.status = it.status?.getStatusCode()
                    },
                    data: json_request
                )
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            ! method.getClassScope().safelyGetVariableOfName('slowSimpleRestClient')

    }
}

