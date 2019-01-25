package afip.visitors

import org.codehaus.groovy.ast.ClassNode
import org.codehaus.groovy.ast.ConstructorNode
import org.codehaus.groovy.ast.FieldNode
import org.codehaus.groovy.ast.MethodNode

class ClassVisitor extends BasicVisitor {
    private ClassNode node
    private ConstructorNode constructor
    private HashMap<String, MethodNode> methods
    private HashMap<String, MethodNode> getters
    private HashMap<String, FieldNode> fields

    /** Constructor */
    ClassVisitor() {
        this.getters = new HashMap<>()
        this.fields = new HashMap<>()
        this.methods = new HashMap<>()
    }

    /** Visit a class node */
    void visit(ClassNode node) {
        this.node = node
        super.visitClass(node)
    }

    /** Get the methodNodes registered during the visitation */
    ArrayList<MethodNode> getMethods() {
        assert node
        return this.methods.values()
    }

    /** Get the getterNodes registererd during the visitation */
    ArrayList<MethodNode> getGetters() {
        assert node
        return this.getters.values()
    }

    ArrayList<FieldNode> getFields() {
        return this.fields.values()
    }

    @Override
    /** When finding a field, just save it and stop visitation */
    void visitField(FieldNode fieldNode) {
        fields.put(fieldNode.getName(), fieldNode)
    }


    /** Visit a constructor or method and save it as it corresponds */
    void visitConstructorOrMethod(MethodNode methodNode, boolean isConstructor) {
        isConstructor ? _visitConstructor(methodNode) : _visitMethod(methodNode)
    }

    /** Constructors are pretty uninteresting for us at this stage, but save it anyway */
    private void _visitConstructor(ConstructorNode constructorNode) {
        constructor = constructorNode
    }

    /** Visit the methodNodes. If it's a getter, it will save it in the getterNodes list too */
    private void _visitMethod(MethodNode methodNode) {
        String methodName = methodNode.getName()
        if (methodName.startsWith('get') && methodName != 'get' && methodNode.getParameters().size() == 0) {
            registerGetter(methodNode)
        }
        registerMethod(methodNode)
    }

    private void registerGetter(MethodNode methodNode) {
        getters.put(methodNode.getName(), methodNode)
    }

    private void registerMethod(MethodNode methodNode) {
        methods.put(methodNode.getName(), methodNode)
    }

}
