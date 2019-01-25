package afip.scopes

import afip.utils.Create
import afip.visitors.ClassVisitor
import org.apache.log4j.BasicConfigurator
import org.codehaus.groovy.ast.ClassNode
import spock.lang.Specification

class MethodTest extends Specification {
    def setupSpec() {
        BasicConfigurator.configure()
    }
    def "should create method scope"(){
        when:
            def code = """
                         class Test{
                            String cleaner(c) {
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
            def cvisitor = new ClassVisitor()
            cvisitor.visit(classNode)
            def methodNode = cvisitor.getMethods().reverse()[0]
            def method = new Method(methodNode,null)
        then:
            method.hasDeclaredVariable("a")
            method.hasDeclaredVariable("c")
            method.hasDeclaredVariable("return")
    }
}
