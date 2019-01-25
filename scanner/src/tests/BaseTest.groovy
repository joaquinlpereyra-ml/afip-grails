import afip.scopes.ClassScope
import afip.scopes.Method
import afip.utils.Create
import org.apache.log4j.BasicConfigurator
import org.codehaus.groovy.ast.ClassNode
import spock.lang.Specification

class BaseTest extends Specification {

    def setupSpec() {
        BasicConfigurator.configure()
    }
    protected  ClassScope ClassScope(String code) {
       return new ClassScope(AST(code).get(1) as ClassNode)
    }
    protected  Method MethodScope(String code) {
        def clazz = ClassScope(code)
        return clazz.getMethodOfName("run")
    }

    protected  ArrayList<Method> MethodScopes(String code) {
        def clazz = ClassScope(code)
        return clazz.getMethods()
    }

    protected AST(String code) {
        return Create.AST(code)
    }
}
