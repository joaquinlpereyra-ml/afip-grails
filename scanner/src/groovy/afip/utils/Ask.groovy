package afip.utils

import org.codehaus.groovy.ast.ASTNode
import org.codehaus.groovy.ast.expr.*
import org.codehaus.groovy.ast.stmt.BlockStatement
import org.codehaus.groovy.ast.stmt.EmptyStatement
import org.codehaus.groovy.ast.stmt.IfStatement
import org.codehaus.groovy.ast.stmt.ReturnStatement
import org.codehaus.groovy.ast.stmt.ThrowStatement

class Ask {

    /** Is the binaryExpression declaring a variable? */
    static Boolean isVariable(BinaryExpression binaryExpression) {
        Boolean weConsiderItAVar = isNodeVariableMaterial(binaryExpression.getLeftExpression())
        Boolean isNormalVariable = declaresNormalVariable(binaryExpression)
        Boolean isAddingValuesToCollection = isAddingValuesToCollection(binaryExpression)
        Boolean isDeclaringCollection = isDeclaringCollection(binaryExpression)
        return weConsiderItAVar && (isNormalVariable || isAddingValuesToCollection || isDeclaringCollection)
    }

    static Boolean endsInmediatly(IfStatement ifStatement) {
        def emptyElse = ifStatement.getElseBlock() instanceof EmptyStatement
        def hasIfBlock = ifStatement.getIfBlock() instanceof BlockStatement
        if (!emptyElse || !hasIfBlock) return false
        return Ask.throwsImmediately(ifStatement) || Ask.returnsInmediately(ifStatement)
    }

    static Boolean returnsInmediately(IfStatement ifStatement) {
        def ifBlock = ifStatement.getIfBlock() as BlockStatement
        def onlyReturns = ifBlock.getStatements().size() == 1 && ifBlock.getStatements().first() instanceof ReturnStatement
        return onlyReturns
    }

    /** Will tell you if the only statement found inside an if condition is a throw statement */
    static Boolean throwsImmediately(IfStatement ifStatement) {
        def ifBlock = ifStatement.getIfBlock() as BlockStatement
        def onlyThrows = ifBlock.getStatements().size() == 1 && ifBlock.getStatements().get(0) instanceof ThrowStatement
        return onlyThrows
    }

    static Boolean isMapOrList(Expression expression) {
        return (expression instanceof MapExpression || expression instanceof ListExpression)
    }

    /**
     * Inspect the binary expression and decides if it declares a map.
     * Map declarations look like one of these:
     *      def a = ['some': 'map']
     * @param binaryExpression
     * @return True if binary expression was declaring a map, false otherwise.
     */
    static Boolean isDeclaringCollection(BinaryExpression binaryExpression) {
        Boolean isLeftSideVariable = isNodeVariableMaterial(binaryExpression.getLeftExpression())
        assert !(binaryExpression.getRightExpression() instanceof MapExpression && binaryExpression.getRightExpression() instanceof  ListExpression)
        Boolean isRightSideCollection = binaryExpression.getRightExpression() instanceof MapExpression ^ binaryExpression.getRightExpression() instanceof  ListExpression
        Boolean isUsingAssignmentOperator = isUsingAssignmentOperator(binaryExpression)
        return isLeftSideVariable && isRightSideCollection && isUsingAssignmentOperator
    }

    /**
     * Inspect the binary expression and decides if declares a normal variable.
     * Normal afip.variables take one of the following forms, where b is NOT a map.
     *      def a = b
     *      a = b
     * @param binaryExpression
     * @return True if binary expression is declaring a normal variable, False otherwise
     */
    static Boolean declaresNormalVariable(BinaryExpression binaryExpression) {
        Boolean isUssingAssignmentOperator = isUsingAssignmentOperator(binaryExpression)
        Boolean isLeftSideVariable = isNodeVariableMaterial(binaryExpression.getLeftExpression())
        Boolean isNotACollection = (! isDeclaringCollection(binaryExpression))
        Boolean isNotAddingValuesToACollection = (! isAddingValuesToCollection(binaryExpression))
        return isUssingAssignmentOperator && isLeftSideVariable && isNotACollection && isNotAddingValuesToACollection
    }

    /**
     * Decide whether the binary expression is setting a property.
     */
    static Boolean isSettingProperty(BinaryExpression binaryExpression) {
        return binaryExpression.getLeftExpression() instanceof PropertyExpression
    }

    static Boolean isAddingValuesToCollection(MethodCallExpression methodCallExpression){
        Expression variable = methodCallExpression.getReceiver()
        return isUsingSomeMethodToAddToAList(methodCallExpression) && variable instanceof VariableExpression

    }

    static Boolean hasExplicitReceiver(MethodCallExpression methodCallExpression) {
        return methodCallExpression.getReceiver().getText() != 'this'
    }

    /**
     * Inspect a binary expression and decides if it is adding value to a map.
     * Adding value to a map takes one of the following forms:
     *      map << ['some': 'value']
     *      map['some'] = 'value'
     * @param binaryExpression
     * @return True if the binary expression is adding value to a map
     */
    static Boolean isAddingValuesToCollection(BinaryExpression binaryExpression) {
        Expression leftSide = binaryExpression.getLeftExpression()

        Boolean isLeftSideVariable = isNodeVariableMaterial(binaryExpression.getLeftExpression())
        Boolean usesArrowOperator = isUsingArrowOperator(binaryExpression)
        Boolean usesAssignmentOperator = isUsingAssignmentOperator(binaryExpression)

        assert !(usesArrowOperator && usesAssignmentOperator)

        Boolean usesEitherArrowOrAssignment = usesArrowOperator ^ usesAssignmentOperator
        Boolean correctOperatorIfAssignmentOperator = ! usesAssignmentOperator ?: isBinaryAndOperatorIsBracket(leftSide)
        return isLeftSideVariable && usesEitherArrowOrAssignment && correctOperatorIfAssignmentOperator
    }

    static Boolean isBinaryAndOperatorIsBracket(Expression expression) {
        return expression instanceof BinaryExpression && expression.getOperation().getText() == '['
    }

    static Boolean isMapExpression(Expression expression) {
        return expression instanceof MapExpression
    }

    /**
     * Traverses the left side of the binary expression until it stops being a binaryExpression,
     * then returns True if the left side of the bottom binary expression is a VariableExpression.
     * Example of a code which returns True:
     * map['a'] = 'b'
     * A simplified AST of this snippet is:
     *        BINARY
     *  BINARY      CONS
     * VAR  CONST    CONS
     * @param binaryExpression
     */
    static Boolean isLeftSideVariable(BinaryExpression binaryExpression) {
        while (binaryExpression.getLeftExpression() instanceof BinaryExpression) {
            binaryExpression = binaryExpression.getLeftExpression()
        }
        return isNodeVariableMaterial(binaryExpression.getLeftExpression())
    }

    /**
     * The only nodes on the left of a binary expression from which we can create a variable are
     * VariableExpression themselves or PropertyExpressions.
     */
    static Boolean isNodeVariableMaterial(ASTNode node) {
        return (node instanceof VariableExpression || node instanceof PropertyExpression)
    }

    /** Return True if the binary expression uses the '<<' operator */
    static Boolean isUsingArrowOperator(BinaryExpression binaryExpression) {
        return binaryExpression.getOperation().getText() == '<<'
    }

    /** Return True if the binary expression uses the '=' operator */
    static Boolean isUsingAssignmentOperator(BinaryExpression binaryExpression) {
        return binaryExpression.getOperation().getText() == '='
    }

    static Boolean isUsingSomeMethodToAddToAList(MethodCall method){
        HashSet<String> methodsToAdd = ["add","push", "addAll"]
        return methodsToAdd.contains(method.getMethodAsString()) && method.getArguments() instanceof ArgumentListExpression
    }


    static Boolean isUsingSomeMethodToAddToAMap(MethodCall method){
        HashSet<String> methodsToAdd = ["put"]
        return methodsToAdd.contains(method.getMethodAsString()) && method.getArguments() instanceof ArgumentListExpression
    }


    static Boolean pureNamedArgumentsMethodCall(MethodCall method) {
        assert method.getArguments() instanceof  TupleExpression

        TupleExpression arguments = method.getArguments()
        if (! arguments ) { return false }
        List<Expression> argumentExpressions = arguments.getExpressions()
        List<ArgumentListExpression> namedArgumentListsExpressions = argumentExpressions.findAll { node ->
            node instanceof NamedArgumentListExpression
        }
        return namedArgumentListsExpressions.size() > 0
    }
}

