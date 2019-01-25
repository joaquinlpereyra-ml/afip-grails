import afip.variables.CollectionEntry
import afip.variables.CollectionVariable
import afip.variables.NormalVariable
import afip.vulns.Vuln

class VariableTests extends BaseIntegrationTest {

   def "should see config"() {
       when:
         def code = """
            grails.config.locations = [Recommendations]
         """
         visitAndCreateAndDetectFromMethod(code)
       then:
        method.getLastDeclarationOf('grails.config.locations')
   }

    def "should see normal variable"() {
        when:
            def code = """
                def a = b
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf("a")
    }

    def "should add value to unknwon collection"() {
        when:
            def code = """
                userPost.context << [pwd_generation_status: "generated"]
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            method.getLastDeclarationOf('userPost.context')
    }


    def "should see method named arguments as variables"() {
        when:
            def code = """
            def a = 'asd'
            def b = [some: "model"]
            render(text: a, model: b)
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            CollectionVariable render = method.getLastDeclarationOf("render")
            CollectionEntry text = render.getEntry("text")
            CollectionEntry model = render.getEntry("model")
            method.getLastDeclarationOf(text.getValue().getText()) instanceof NormalVariable
            method.getLastDeclarationOf(model.getValue().getText()) instanceof CollectionVariable
    }

    def "should see method positional arguments as variables"() {
        when:
            def code = """
                 def a = 'some text'
                 render(a, 'some text')
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            CollectionVariable render = method.getLastDeclarationOf("render")
            render.getEntries().size() == 2
            render.getEntry('0').getValue().getText() == 'a'
            method.getLastDeclarationOf('a').getValue().getText() == 'some text'
            render.getEntry('1').getValue().getText() == 'some text'
    }

    def "should see json variable as tainted"() {
        when:
            def code = """
                 def json = request.JSON
            """
            visitAndCreateAndDetectFromMethod(code)
        then:
            Vuln.getSubclasses().forEach({ vuln -> method.getLastDeclarationOf("json").canTrigger(vuln)})

    }
}
