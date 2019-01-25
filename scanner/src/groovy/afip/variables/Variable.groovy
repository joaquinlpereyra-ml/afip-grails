package afip.variables

import afip.errors.NotAVariable
import afip.errors.UnknownSourceForVariable
import afip.scopes.Scope
import afip.utils.Ask
import afip.utils.Create
import afip.utils.Extract
import afip.visitors.BasicVisitor
import afip.vulns.Vuln
import org.codehaus.groovy.ast.ASTNode
import org.codehaus.groovy.ast.FieldNode
import org.codehaus.groovy.ast.MethodNode
import org.codehaus.groovy.ast.Parameter
import org.codehaus.groovy.ast.expr.*
import org.codehaus.groovy.ast.stmt.ReturnStatement

/**
 * An abstract class to represent afip.variables.
 */
abstract class Variable implements Dangerous {
    protected Expression node
    protected String name
    protected Boolean tainted
    protected Boolean isConstructor = false
    protected Expression value
    protected HashMap<Class<Vuln>, Integer> untaintedBranches
    protected HashSet<Class<Vuln>> _triggerableVulns
    protected Scope scope
    protected Integer branchesOnLastDeclaration
    protected ASTNode originalNode

    Expression getNode() { return this.node }
    Scope getScope() { return this.scope}
    Integer getBranchesOnLastDeclaration() { return this.branchesOnLastDeclaration }
    String getName() { return this.name }
    Expression getValue() { return this.value }
    Boolean hasValue() { return getValue() != null }

    Integer getUntaintedBranchesFor(Class<Vuln> vulnClass) {
        return untaintedBranches.get(vulnClass)
    }

    static Variable createAndRegister(ASTNode node, Integer branches, Scope scope) throws NotAVariable, UnknownSourceForVariable {
        assert branches >= 1

        Variable var = createVariable(node, scope, branches)
        scope.addVariable(var, branches)
        var.setOriginalNode(node)
        if (var instanceof CollectionVariable) {
            for (CollectionEntry entry : var.getEntries().flatten()) {
                entry.getVariable().setOriginalNode(node)
            }
        }

        return var
    }

    boolean isConstructor(){
        isConstructor
    }

    void reset(){
        untaintedBranches = new HashMap<>()
        for (Class<? extends Vuln> vuln : Vuln.getSubclasses()){
            untaintedBranches.put(vuln,0)
        }
        _triggerableVulns = new HashSet<>()
    }

    protected setOriginalNode(ASTNode node) {
        originalNode = node
    }

    ASTNode getOriginalNode() {
        return originalNode
    }

    boolean equals(Object other) {
        return (other instanceof Variable && this.getName() == other.getName() && other.getValue() == this.getValue())
    }

    String originalToString() {
        return super.toString()
    }

    int hashCode() {
        return (this.getName() + this.getValue().getText()).hashCode()
    }

    String toString() {
        return this.getClass().getSimpleName() + " " + this.getName() + " " + this.getValue().getText() + "\n"
    }

    Boolean isOriginal() {
        return getReferencedVariables().isEmpty()
    }

    ArrayList<Variable> recursiveGetReferencedVariables(ArrayList<Variable> alreadyReferenced) {
        if (isOriginal()) { return [this] }

        ArrayList<Variable> references = getReferencedVariables()
        ArrayList<Variable> searchable = references.minus(alreadyReferenced)
        if ( references.collect { it.getName() }.contains(this.getName())) { return [this] }

        ArrayList<Variable> originals = []
        ArrayList<Variable> referenced = references + alreadyReferenced
        originals.addAll ( searchable.collect { it.recursiveGetReferencedVariables(referenced) }.flatten() )
        return originals
    }

    ArrayList<Variable> getOriginalVariables() {
        try {
            return recursiveGetReferencedVariables([])
        } catch (StackOverflowError ignored) {
            // this is a recursive, ugly, process.
            // better abort if something goes wrong.
            return []
        }
    }

    ArrayList<Variable> getReferencedVariables() {
        ArrayList<Variable> variablesReferenced = new ArrayList<>()

        Scope scope = getScope()
        BasicVisitor variableVisitor = new BasicVisitor() {
            public ArrayList<String> namesOfVariablesUsed = new ArrayList<>()
            @Override
            void visitVariableExpression(VariableExpression expression) {
                namesOfVariablesUsed.add(expression.getName())
                super.visitVariableExpression(expression)
            }
        }
        variableVisitor.visit([getValue()])
        variableVisitor.namesOfVariablesUsed.each{ variableName ->
                Variable var = scope.safelyGetVariableOfName(variableName)
                if (var) { variablesReferenced.add(var)}
        }
        return variablesReferenced
    }

    /**
     * Creates a new variable using the binary expression. The method will decide if it should create a Normal Variable,
     * create a new Map Variable or add entries to an existing Map Variable. Call only making sure
     * the variable is not already registered.
     * @param binaryExpression: the binary expression to use as a source for a variable.
     * @param isLocal: True if the variable is local, False otherwise.
     * @return a new Variable
     * @throws UnknownSourceForVariable: if the binary expression doesn't declare a variable in any known form.
     */
     static Variable createVariable(BinaryExpression binaryExpression, Scope scope, Integer branches) throws
            UnknownSourceForVariable, NotAVariable {

        if (! Ask.isVariable(binaryExpression)) {
            throw new NotAVariable()
        }

        Variable desiredVariable

        if (Ask.isDeclaringCollection(binaryExpression)) {
            desiredVariable = new CollectionVariable(binaryExpression, scope, branches)
        } else if (Ask.isAddingValuesToCollection(binaryExpression)) {
            String mapName = Extract.variableName(binaryExpression)
            if (! (scope.canAccessVariable(mapName))) {
                createAndRegister(Create.emptyMapDeclaration(mapName), branches, scope)
            }

            desiredVariable = scope.getVariableOfName(mapName)
            if (! (desiredVariable instanceof CollectionVariable)) {
                desiredVariable = desiredVariable.changeTypeToCollection(branches)
            }
            desiredVariable = desiredVariable as CollectionVariable
            desiredVariable.addEntry(binaryExpression, scope, branches)
        } else if (Ask.declaresNormalVariable(binaryExpression)) {
            desiredVariable = new NormalVariable(binaryExpression, scope, branches)
        } else {
            throw new UnknownSourceForVariable()
        }
        return desiredVariable
    }

    static ReturnVariable createVariable(ReturnStatement returnStatement, Scope scope, Integer _) {
        return new ReturnVariable(returnStatement, scope)
    }

    static ParameterVariable createVariable(Parameter parameter, Scope scope, Integer _) {
        return new ParameterVariable(parameter, scope)
    }

    static Variable createVariable(FieldNode fieldNode, Scope scope, Integer branches) {
        Expression initial = fieldNode.getInitialExpression() ?: new EmptyExpression()
        initial.setColumnNumber(fieldNode.getColumnNumber())
        initial.setLineNumber(fieldNode.getLineNumber())
        createFake(fieldNode.getName(), initial, scope, branches)
    }

    static Variable createVariable(VariableExpression variableExpression, Scope scope, Integer branches) {
        return new UnknownVariable(variableExpression, scope, branches)
    }

    static Variable createVariable(ConstructorCallExpression constructorCallExpression, Scope scope, Integer branches) {
        ArrayList<MapEntryExpression> args = Extract.argumentsFromMethodCall(constructorCallExpression)
        MapExpression artificialArgMap = new MapExpression(args)
        BinaryExpression artificalBinarry = Create.assignmentFromTemplate(constructorCallExpression.getType().getText(), artificialArgMap, constructorCallExpression)
        def res = createVariable(artificalBinarry, scope, branches)
        res.isConstructor = true
        res
    }

    static private createArtificalBinaryFromArtificialName(String artificialName, MethodCallExpression methodCall, Scope scope, Integer branches) {
        BinaryExpression artificialBinary = Create.assignmentFromTemplate(artificialName, new MapExpression(), methodCall)
        createVariable(artificialBinary, scope, branches)
    }

    static Variable createVariable(MethodCallExpression methodCall, Scope scope, Integer branches) {
        String artificialName = Extract.variableName(methodCall)
        ArrayList<MapEntryExpression> arguments = Extract.argumentsFromMethodCall(methodCall)
        MapExpression artificialMap = new MapExpression(arguments)
        BinaryExpression artificialNode

        // Beware, young padawan. I loved you. Good luck.
        if ( Ask.isUsingSomeMethodToAddToAList(methodCall) || Ask.isUsingSomeMethodToAddToAMap(methodCall)) {
            if (! scope.canAccessVariable(artificialName) ) { createArtificalBinaryFromArtificialName(artificialName, methodCall, scope, branches) }
            if (Ask.isUsingSomeMethodToAddToAList(methodCall)) {
                Integer index = 0
                for (MapEntryExpression arg : arguments) {
                    artificialNode = Create.addValueToMapWithArrowsExpression(artificialName, index.toString(), arg.getValueExpression())
                    index++
                }
            } else {
                for (MapEntryExpression arg : arguments) {
                    artificialNode = Create.addValueToMapWithArrowsExpression(artificialName, arg.getKeyExpression().getText(), arg.getValueExpression())
                }
            }
        } else if ( Ask.hasExplicitReceiver(methodCall) ){
            Variable var = scope.safelyGetVariableOfName(methodCall.getReceiver().getText())
            if (var) {
                var.getAllLivingDefinitions().eachWithIndex { livingDef, i ->
                    ConstantExpression key = new ConstantExpression("receiver" + i.toString())
                    artificialMap.addMapEntryExpression(new MapEntryExpression(key, Create.variableExpression(livingDef.getName())))

                    // dealing with side effects on a method.
                    // let's take the XmlExternalEntitiesVuln.
                    // def vulnerableXSSParser = new XmlSlurper();
                    // if (something) {
                    //    vulnerableXSSParser.setFeature("http://xml.org/sax/features/external-general-entities", false)
                    // }
                    // vulnerableXSSParser.parseText(something)
                    // if i have an object and a method which modifies that object
                    // the branches on the original object WILL NEVER return to a lower value.
                    // so vulnerableXssParser on creation has 1 branch, one possible state.
                    // when it enters the if, it has two.
                    // but when it gets outside the if... there's still TWO possible states.
                    if (branches > livingDef.branchesOnLastDeclaration) {
                        livingDef.branchesOnLastDeclaration = branches
                    }
                }
            } else {
                artificialMap.addMapEntryExpression(new MapEntryExpression(new ConstantExpression("receiver0"), methodCall.getObjectExpression()))
            }
            artificialNode = Create.assignmentFromTemplate(artificialName, artificialMap, methodCall)
        }
        else {
            artificialNode = Create.assignmentFromTemplate(artificialName, artificialMap, methodCall)
        }


        // If there are no arguments and the function being called has the same name
        // as a function to add elements to a list or dictionary, we're screwed, as the
        // artificialNode is never init'd.
        // this is a horrible solution because we need to ship pretty soon, ack.
        // a real solution would be to try to 'track' all functions definitions
        // and attach them to a class, that way, we can know they are not the 'real'
        // adding functions, but overwritten versions of those
        // right know, we're just knowingly feeding false data to afip telling it the method call
        // was just its name equaling an empty map.
        // this SHOULD NOT have any unintended consequences, as by definition an nullary function
        // should not carry a tainted variable. it is nevertheless ugly and stupid.
        // even then, what if an overloaded version of, for example, the `add` function actually takes params?
        // then we sould be telling afip to add elements to a list which doesn't even exist!
        // it will be created artificially above (the scope would not be able to reach it) but
        // whether this may lead to some false positives or not is up to discusion
        if (! artificialNode) {
            artificialNode = Create.assignmentFromTemplate(artificialName, artificialMap, methodCall)
        }

        Variable variable = createVariable(artificialNode, scope, branches)
        assert variable instanceof CollectionVariable
        return variable
    }

    protected Variable changeTypeToCollection(Integer branches) {
        this.getScope().removeVariable(this)
        return createAndRegister(Create.emptyMapDeclaration(this.getName()), branches, getScope())
    }

    /**
     * Creates a fake binary-expression based variable, but it DOES NOT register it on the scope.
     * Mainly used to give a standard, normal-looking NormalVariable to our CollectionEntries.
     * @param name
     * @param value
     * @param scope
     * @param branches
     * @return
     */
    static protected Variable createFake(String name, Expression value, Scope scope, Integer branches) {
        BinaryExpression artificialBinary = Create.assignmentFromTemplate(name, value, value)
        Variable var =  createVariable(artificialBinary, scope, branches)
        var.setOriginalNode(artificialBinary)
        return var
    }

    protected void setFields(String name, Expression value, Expression node, Scope scope, Integer branches) {
        this.name = name
        this.value = value ?: new EmptyExpression()
        this.node = node
        this.branchesOnLastDeclaration = branches
        this._triggerableVulns = new HashSet<Class<Vuln>>()
        this.untaintedBranches = new HashMap<Class<Vuln>, Integer>()
        this.scope = scope
        for (Class vulnClass : Vuln.getSubclasses() ) { untaintedBranches.put(vulnClass, 0) }
    }

    ArrayList<Variable> getAllDefinitions() {
        return scope.getAccessibleVariables().findAll { var -> var.getName() == this.getName() }
    }

    ArrayList<Variable> getAllLivingDefinitions() {
        ArrayList<Variable> allDefs = getAllDefinitions()
        Integer amountOfDefs = allDefs.size()
        Integer irrelevantDefs = amountOfDefs - getBranchesOnLastDeclaration()

        // ok, so, if we are on only one branch, we need ONE EXTRA living defition to pass taint on
        // in case this is a self-referenced branch
        // def a = params.a (a = tainted)
        // a = 'hola' + a (a still tainted)
        // a = a + '2'
        // if we just returned the last, a would be untainted, as a = 'hola' + unkown variable is not tainted :)
        if (getBranchesOnLastDeclaration() == 1 && amountOfDefs >= 2) {
            // if penultimate variable is a paramaterVariable it should not count as a living definition
            if(!(getAllDefinitions()[-2] instanceof ParameterVariable)) {
                return [getAllDefinitions()[-2], getAllDefinitions().last()]
            }
        }
        return getAllDefinitions().drop(irrelevantDefs)
    }

    Integer amountOfLivingDefinitions() {
        return getAllLivingDefinitions().size()
    }

}
