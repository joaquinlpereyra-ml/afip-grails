package afip.visitors

import org.codehaus.groovy.ast.ASTNode
import org.codehaus.groovy.ast.ClassCodeVisitorSupport

/**
 * A class to act as a super class for all the afip.visitors.
 */
abstract class Visitor extends ClassCodeVisitorSupport {
    abstract void visit(ArrayList<ASTNode> nodes)
}
