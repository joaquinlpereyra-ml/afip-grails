package afip.utils

import afip.scopes.ClassScope
import afip.scopes.Controller
import afip.scopes.Project
import org.codehaus.groovy.ast.ASTNode
import org.codehaus.groovy.ast.ClassNode
import org.codehaus.groovy.ast.builder.AstBuilder
import org.codehaus.groovy.ast.expr.*
import org.codehaus.groovy.control.CompilePhase
import org.codehaus.groovy.syntax.Token
import org.codehaus.groovy.syntax.Types

class Create {
    /** Use this to build AST trees from a string of groovy code. */
    static ArrayList<ASTNode> AST(String code) {
        // whatever you do, DO NOT change the CompilePhase.
        new AstBuilder().buildFromString(CompilePhase.CONVERSION, false, code)
    }
    static ClassScope ClassScope(String code) {
        return new ClassScope(AST(code).get(1) as ClassNode)

    }

    static Project MockProject() {
        Project mock = new Project() {
            boolean hasServiceOfName(String n) {
                false
            }
        }
        mock
    }

    static Controller Controller(String code) {
        return new Controller(AST(code).get(1) as ClassNode,":D")
    }

    /** Sets the line and column of all the nodes to the values given in line and column */
    static private setLineAndColumnInAll(ArrayList<ASTNode> nodes, Integer line, Integer column) {
        nodes.each { node ->
            node.setLineNumber(line)
            node.setColumnNumber(column)
        }
    }

    /** Use this to create artificial method calls from a string with the method namesi and a named argument list of args
     * When using, consider the methodCall will be bound to 'this'
     */
    static MethodCallExpression methodCall(String methodName, NamedArgumentListExpression arguments) {
        VariableExpression binding = new VariableExpression('this')
        MethodCallExpression methodCall =  new MethodCallExpression(binding, methodName, arguments)
        return methodCall
    }

    /** Create a new empty map declaration with the given name */
    static BinaryExpression emptyMapDeclaration(String name) {
        return assignment(name, new MapExpression())
    }

    /** Creates a new binary expression with a given name and value taking its metadate from the template node */
    static BinaryExpression assignmentFromTemplate(String artificialName, Expression artificialValue, ASTNode template) {
        // for some reason, node's lines are offset by one, so we compensate here :)
        return assignment(artificialName, artificialValue, template.getLineNumber() - 1, template.getColumnNumber())
    }

    /** Create an artificial assignment to a variable of artificialName. The value of said variable will be the
     * expression passed as artificialValue.
     */
    static BinaryExpression assignment(String artificialName, Expression artificialValue, Integer line = -1, Integer column = -1) {
        VariableExpression artificialVariable = new VariableExpression(artificialName)
        Token assignmentToken = new Token(Types.ASSIGN, '=', line, column)
        BinaryExpression artificialBinary = new BinaryExpression(artificialVariable, assignmentToken, artificialValue)
        setLineAndColumnInAll([artificialBinary, artificialVariable, artificialValue], line, column)
        return artificialBinary
    }

    /** Create a new variable expression with the given name */
    static VariableExpression variableExpression(String artificialName) {
        return new VariableExpression(artificialName)
    }

    /** Create a new binary expression which adds a key with the value on value to the map of mapName. In normal groovy
     * code, this looks like this: mapName << [keyName: value]
     */
    static BinaryExpression addValueToMapWithArrowsExpression(String mapName, String keyName, Expression value) {
        VariableExpression artificialReceiver = new VariableExpression(mapName)
        Token arrowToken = new Token(Types.LEFT_SHIFT, '<<', -1, -1)
        MapExpression artificialMap = new MapExpression([new MapEntryExpression(new VariableExpression(keyName), value)])
        BinaryExpression artificialArrowyExpression = new BinaryExpression(artificialReceiver, arrowToken, artificialMap)
        return artificialArrowyExpression
    }
}


