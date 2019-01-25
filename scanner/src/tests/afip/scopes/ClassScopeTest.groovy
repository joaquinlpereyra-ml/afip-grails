package afip.scopes

import afip.utils.Create
import org.apache.log4j.BasicConfigurator
import org.codehaus.groovy.ast.ClassNode
import spock.lang.Specification

class ClassScopeTest extends Specification {
    def setupSpec() {
        BasicConfigurator.configure()
    }
    def "should create class scope"(){
        when:
            def code = """
                         class Test{
                            
                            String paco
                            String getWololo(){
                                wololo 
                            }
                            
                            String cleaner() {
                                a = a.encodedAsHTML()                    
                            }
                            void notMethod(){
                                def b = params.danger
                                b = cleaner(b)
                                render(model: b)
                            }
                         }
                    """
            def ast = Create.AST(code)
            def classNode = ast.get(1) as ClassNode
            def klass = new ClassScope(classNode)
        then:
            !klass.hasDeclaredVariable("a")
            !klass.hasDeclaredVariable("b")
            !klass.hasDeclaredVariable("return")
            klass.hasDeclaredVariable("paco")
            klass.hasDeclaredVariable("wololo")
            klass.hasMethodOfName("cleaner")
            klass.hasMethodOfName("notMethod")
    }
}
