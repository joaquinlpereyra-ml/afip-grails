package afip.utils

import org.codehaus.groovy.ast.expr.*

class Extract {
    /**
     * Recursively reach the leftmost node of the binary expression which still is a binary expression,
     * and return the name of the VariableExpression there or the PropertyExpression.
     * @precondition: the left side of the leftmost node which still is a binary expression must be a variable or a property.
     * @param binaryExpression
     * @return The variable or property name as a string.
     */
    static String variableName(BinaryExpression binaryExpression) {
        Expression leftMostNode = binaryExpression
        while (leftMostNode instanceof BinaryExpression) {
            leftMostNode = (leftMostNode as BinaryExpression).getLeftExpression()
        }
        assert Ask.isNodeVariableMaterial(leftMostNode)
        Expression variable = leftMostNode
        String name = variable.getText()
        return name != 'loadFactor' ? name : 'loadFactorXXX'
    }

    /**
     * Return the artificial name of our representation of a method call as a model.
     * @param methodCall
     * @return
     */
    static String variableName(MethodCallExpression methodCall) {
        String name
        if (Ask.isUsingSomeMethodToAddToAList(methodCall) || Ask.isUsingSomeMethodToAddToAMap(methodCall)) {
            name = methodCall.getReceiver().getText()
        } else {
            name = methodCall.getMethodAsString() ?: 'gString'
        }
        return name != 'loadFactor' ? name : 'loadFactorXXX'
    }

    static private ArrayList<MapEntryExpression> createAnonymousEntriesFromPositionalParams(ArgumentListExpression args) {
        ArrayList<MapEntryExpression> anonymousArgs = []

        // in a methdoCallExpression, named parameters are represented by a MapEntryExpression, so we filter them
        args = args.findAll { arg -> ! (arg instanceof MapEntryExpression || arg instanceof NamedArgumentListExpression) }

        args.getExpressions().eachWithIndex { Expression arg, int position ->
            anonymousArgs.add(new MapEntryExpression(Create.variableExpression(position.toString()), arg))
        }
        return anonymousArgs
    }

    /** Return the arguments of a methodCall as an arraylist of mapEntryExpressions. */
    static ArrayList<MapEntryExpression> argumentsFromMethodCall(MethodCall methodCall) {
        assert methodCall.getArguments() instanceof TupleExpression

        // silly automatic method injected into scripts. messes up with amount of living definitions afterwards
        if (methodCall.getMethodAsString() == 'runScript') { return [] }

        // for some reason definitions like render(text: 'hola') are TupleExpressions. Whatever.
        TupleExpression rawArgs = methodCall.getArguments()
        ArgumentListExpression args = rawArgs instanceof TupleExpression ? rawArgs.getExpressions() : rawArgs

        ArrayList<MapEntryExpression> anonymousParams = new ArrayList<>()
        ArrayList<MapEntryExpression> namedParams = new ArrayList<>()

        // We first deal with anonymous arguments, like render('text') or map.put('someKey', 'someValue')
        // Methods to add to a map, like map.put('key', 'value'), are anonymous, but we can obviously retrieve
        // the key easily and pretend we know it, so they will be added to the named params list
        if (!Ask.isUsingSomeMethodToAddToAMap(methodCall) ) {
            anonymousParams.addAll(createAnonymousEntriesFromPositionalParams(args))
        } else {
            Integer argumentListSize = args.size()
            for (int i = 0; i < argumentListSize; i = i + 2) {
                namedParams.add(new MapEntryExpression(new VariableExpression(args[i].getText()), args[i+1]))
            }
        }
        // Let's now deal with the named arguments.

        // This is the pure named case. Something like render(model: [something: "other thing"], text: "hi")
        if (Ask.pureNamedArgumentsMethodCall(methodCall)) {
             ArrayList<NamedArgumentListExpression> namedArgumentsLists = args.findAll { node ->
                 node instanceof NamedArgumentListExpression
             }
             for (NamedArgumentListExpression namedArgumentList : namedArgumentsLists) {
                 namedParams.addAll(namedArgumentList.getMapEntryExpressions())
             }
        }

        // But there are hybrid cases too, like render('something', text: 'hi'). Groovy apparently has no specific node
        // for this and just interprets this as being render('something', [text: 'hi']). Actually the same happens
        // in the pure case, but there's a node for that. Who knows. Anyway.
        namedParams.addAll(args.getExpressions().findAll { node -> node instanceof MapEntryExpression })

        ArrayList<MapEntryExpression> arguments = new ArrayList<>()
        arguments.addAll(namedParams)
        arguments.addAll(anonymousParams)

        return arguments
    }
}
