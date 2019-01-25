import afip.utils.Create
import afip.visitors.ClassVisitor
import org.codehaus.groovy.ast.ASTNode

/**
 * Created by nlantez on 2/21/17.
 */
class ClassVisitorTests extends BaseIntegrationTest {

        def "class visitor should register the fields of the class. Not the method fields!"() {
            when:
                def code = """
                     class Test{
                        def saludo = "Hola"

                        public void methodTest(){
                            def despedida = "Chau"
                            return 2
                        }

                     }
                """
                ArrayList<ASTNode> ast = Create.AST(code)
                ClassVisitor classVisitor = new ClassVisitor()
                classVisitor.visit(ast.get(1))
            then:
                classVisitor.fields.size() == 1
        }

        def "class visitor should register the getter methods"(){
            when:
            def code = """
                     class Test{
                       public void getA(){
                           return 2
                       }
                       public void methodTest(){
                           return 1
                       }
                     }
                """
            ArrayList<ASTNode> ast = Create.AST(code)
            ClassVisitor classVisitor = new ClassVisitor()
            classVisitor.visit(ast.get(1))
            then:
            classVisitor.getters.size() == 1
        }
}
