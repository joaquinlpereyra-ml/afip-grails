package afip.visitors

import org.codehaus.groovy.ast.ASTNode
import org.codehaus.groovy.ast.ClassNode
import org.codehaus.groovy.ast.MethodNode
import org.codehaus.groovy.control.SourceUnit

/**
 * A small, basic visitor.
 * Really useful to implement anonymous classes to visit the AST tree.
 * It's main subclass is the CodeVisitor
 */
abstract class BasicVisitor extends Visitor {

    BasicVisitor() { }

    /** Extremely mysterious method. Doesn't complain with null, though cries blood if the method is not present */
    SourceUnit getSourceUnit() { null }

    /** Visit the ast. The AST MUST consist of ClassNodes. The first ClassNode will be ignored */
    void visit(ArrayList<ASTNode> AST) {
        for (int i = 0; i < AST.size(); i++) {
            ASTNode node = AST[i]
            if (node instanceof ClassNode) {
                if (i == 1) { continue } // ignore the first class, it is an artificial groovy created one
                ClassNode currentClass = node as ClassNode
                visitClass(currentClass)
            } else if (node instanceof MethodNode) {
                visitMethod(node)
            } else {
                node.visit(this)
            }
        }
    }

    /** Visit a specific class node */
    void visit(ClassNode node) {
        visit([node])
    }
}
