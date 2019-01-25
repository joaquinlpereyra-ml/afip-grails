package afip.scopes

import afip.errors.VariableNotFound
import afip.variables.Variable
import org.apache.commons.logging.LogFactory
import org.codehaus.groovy.ast.ASTNode
import org.codehaus.groovy.ast.ClassNode

class Scope {

    /** Variables container. Must save creations order for AFIP to work properly */
    protected LinkedHashMap<String, ArrayList<Variable>> variables
    /** Parent */
    protected Scope outerScope
    /** Children*/
    protected ArrayList<Scope> innerScope
    protected ASTNode node
    protected static final log = LogFactory.getLog(this)

    /** OuterScope Constructor*/
    Scope(ASTNode node) {
        this.innerScope = new ArrayList<Scope>()
        this.variables = new LinkedHashMap<>()
        this.node = node
    }

    /** InnerScope Constructor*/
    Scope(ASTNode node, Scope outerScope) {
        this.outerScope = outerScope
        this.innerScope = new ArrayList<Scope>()
        this.variables = new LinkedHashMap<>()
        this.node = node
    }

    /**Access */
    Boolean hasReturnVariable(){ return safelyGetVariableOfName("return")}

    /** Getters */
    Scope getOuterScope() throws NullParentException {
        if (!outerScope) {
            throw new NullParentException()
        }
        outerScope
    }

    String getName() {
        def name
        try {
            name = getNode().getName()
        }
        catch (MissingMethodException ignored) {
            name = "Closure"
        }
        name
    }

    HashMap<String, ArrayList<Variable>> getVariables() {
        variables
    }

    ASTNode getNode() {
        node
    }

    List<Scope> getInnerScopes() {
        innerScope
    }

    Variable getVariableOfName(String name) throws VariableNotFound {
        if (!canAccessVariable(name)) {
            throw new VariableNotFound(name)
        }

        Variable desiredVariable
        ArrayList<Variable> possibleMeanings = variables.get(name)
        if (possibleMeanings) {
            desiredVariable = possibleMeanings.last()
        } else {
            desiredVariable = outerScope.getVariableOfName(name)
        }
        return desiredVariable
    }

    ClassScope getClassScope() {
        if (node.getClass() == ClassNode) {
            return this as ClassScope
        } else {
            return outerScope.getClassScope()
        }
    }

    ArrayList<Variable> getReferecedVariables(){
        def referenced = getScopeVariables()
        for (def var : getScopeVariables()){
            def refVars = var.getReferencedVariables()
            referenced.addAll(refVars.findAll(){!referenced.contains(it)})
        }
        return referenced
    }

    ArrayList<Variable> getAccessibleVariables() {
        ArrayList<Variable> variables = getScopeVariables()
        if (outerScope) {
            variables.addAll(outerScope.getAccessibleVariables())
        }
        return variables
    }

    ArrayList<Variable> getScopeVariables() {
        return getVariables().values().flatten()
    }

    /** Returns null instead of throwing exception **/
    Variable safelyGetVariableOfName(String name) {
        if (!canAccessVariable(name)) {
            return null
        }
        return getVariableOfName(name)
    }
    /** Traverse applies closure to each scope. Closure must take the scope as input **/
    void traverse(closure) {
        closure(this)
        if (outerScope) {
            outerScope.traverse(closure)
        }
        //for(Scope innerScope : getInnerScopes()){
        //    innerScope.traverse(closure)
        //}
    }

    /** Creates an innerScopes with an ASTNode **/
    Scope createInnerScopeWith(ASTNode node) {
        Scope scope = new Scope(node, this)
        innerScope.push(scope)
        return scope
    }

    /** Finds an Scope from a given string name **/
    Scope findScopeOfName(String name) throws ScopeNotFoundException{
        def scope
        if (getName() == name) {
           scope = this
        }else{
            for (Scope innerScope : getInnerScopes()){
                try{
                   scope = innerScope.findScopeOfName(name)
                }catch (ScopeNotFoundException ignored) {
                    //keepSearching()
                }
            }
        }
        if(!scope){
            throw new ScopeNotFoundException(this,name)
        }
        return scope
    }

    /**
     * Register a new variable on the scope.
     * @param variable : the variable to be registered.
     * @param branchesPresent : the amount of branches present in the program at the point of registration.
     */
    void addVariable(Variable variable, Integer branchesPresent) {
        def hasDeclaredVariable = hasDeclaredVariable(variable)
        if (!hasDeclaredVariable) {
            this.variables.put(variable.getName(), new ArrayList<Variable>())
        }

        //log.debug(["title": "new variable",
        //          "name": variable.getName(),
        //           "branches": branchesPresent,
        //           "declaredPreviously": hasDeclaredVariable,
        //           "type": variable.getClass().getSimpleName()])

        ArrayList<Variable> declarations = variables.get(variable.getName())
        declarations.push(variable)
    }

    /** Removes variable var **/
    void removeVariable(Variable var) {
        ArrayList<Variable> vars = this.variables.get(var.getName())
        vars.remove(var)
    }

    /** Return whether this scope can access variable of name varName */
    Boolean canAccessVariable(String varName) {
        Variable var = getAccessibleVariables().find { it.getName() == varName }
        return var ? true : false
    }

    /** Return whether the variable var has already been registered in this scope */
    Boolean hasDeclaredVariable(Variable var) {
        for (String registeredVar : getVariables().keySet()) {
            if (registeredVar == var.getName()) {
                return true
            }
        }
        return false
    }

    /** Returns true if variable exist in the scope **/
    Boolean hasDeclaredVariable(String var) {
        for (String registeredVar : getVariables().keySet()) {
            if (registeredVar == var) {
                return true
            }
        }
        return false
    }

    /**
     Returns last declaration of a variable on the Scope. Should only be used in test.
     */
    Variable getLastDeclarationOf(String varName) throws VariableNotFound {
        ArrayList<Variable> vars = getScopeVariables().findAll(){ v -> v.getName() == varName }
        Variable childVar
        for (Scope scope : getInnerScopes()) {
            try {
                childVar = scope.getLastDeclarationOf(varName)
            }
            catch (VariableNotFound _) {
                // Continue searching for var
            }
        }

        if (childVar) {
            return childVar
        } else if (vars.size()) {
            return vars.last()
        } else {
            throw new VariableNotFound(varName)
        }
    }

}
/** Exceptions **/
class NullParentException extends Exception {
   NullParentException(){
       super("root node does not have a getOuterScope")
   }
}

class ScopeNotFoundException extends Exception {
   ScopeNotFoundException(Scope scope,String searchee){
       super("Could not find "+ searchee + " from "+ scope.getName())
   }

    ScopeNotFoundException(String searchee){
        super("Could not find "+ searchee + " anywhere")
    }
}

class ScopePrinter {
    static void print(Scope st){
        print(st.getName()+": ")
        for (def v : st.getScopeVariables() - st.getScopeVariables().last()){
            print(v.getName()+", ")
        }
        println(st.getScopeVariables().last().getName())

        for (Scope child : st.getInnerScopes()){
            printHelper(" ",child)
        }
    }
    private static printHelper(String s, Scope st) {
        print(s+st.getName()+": ")
        for (def v : st.getScopeVariables() - st.getScopeVariables().last()){
            print(v.getName()+", ")
        }
        println(st.getScopeVariables().last().getName())

        for (Scope child : st.getInnerScopes()){
            printHelper(s+" ",child)
        }
    }
}
