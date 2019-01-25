package afip.scopes

import afip.managers.BranchManager
import afip.visitors.ClassVisitor
import afip.visitors.GetterVisitor
import afip.visitors.MethodCanonizator
import afip.visitors.VariableCreator
import org.codehaus.groovy.ast.ClassNode
import org.codehaus.groovy.ast.MethodNode

class ClassScope extends Scope {

    String path

    ClassScope(ClassNode classNode){
        super(classNode)
        extractMethods()
        extractGettersVariables()
    }

    ClassScope(ClassNode classNode, String path){
        super(classNode)
        this.path = path
        extractMethods()
        extractGettersVariables()
    }

    List<Method> getMethods(){innerScopes as List<Method>}
    String getPath(){path}

    /**
     * Postconditions: all the methods of the class are registered in the 'methods' field
     *                 all the methods of the class have been canonized
     */
    private List<Method> extractMethods() {

        def methods = []
        def classVisitor = new ClassVisitor()
        def methodCanonizator = new MethodCanonizator()

        classVisitor.visit(this.node as ClassNode)
        methodCanonizator.visit(classVisitor.getMethods())

        def methodNodes = classVisitor.getMethods().reverse()

        methodNodes.each { node ->
           innerScopes.push(new Method(node,this))
        }

        methods
    }

    private void extractGettersVariables() {

        def classVisitor = new ClassVisitor()
        def methodCanonizator = new MethodCanonizator()

        classVisitor.visit(this.node as ClassNode)
        methodCanonizator.visit(classVisitor.getMethods())
        def getterNodes = classVisitor.getGetters()
        classVisitor.getMethods().reverse()

        GetterVisitor getterVisitor = new GetterVisitor(this, new BranchManager())
        for (MethodNode getter : getterNodes) {
            getterVisitor.visit([getter])
        }

        VariableCreator variableCreator = new VariableCreator(this, new BranchManager())
        variableCreator.visit(classVisitor.getFields())
    }

    /**Testing**/
    Boolean hasMethodOfName(String name){
        try {
            findScopeOfName(name)
            return true
        }catch (ScopeNotFoundException ignored){
            return false
        }
    }

    /**Accessing**/

    /** Should only be called if hasMethodOfName name**/
    Method getMethodOfName(String name){
        findScopeOfName(name) as Method
    }

}

class Controller extends ClassScope{
   Controller(ClassNode classNode, String path) {
       super(classNode,path)
   }
}

class Service extends ClassScope{
   Service(ClassNode classNode,String path) {
       super(classNode,path)
   }
}

class Config extends ClassScope{
   Config(ClassNode classNode,String path) {
       super(classNode,path)
   }
}

class DatabaseFile extends ClassScope{
   DatabaseFile(ClassNode classNode,String path) {
       super(classNode,path)
   }
}

