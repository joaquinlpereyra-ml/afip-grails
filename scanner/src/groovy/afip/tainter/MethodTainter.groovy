package afip.tainter

import afip.errors.CircularAnalysisException
import afip.errors.VariableNotFound
import afip.main.MethodAnalyzer
import afip.scopes.Project
import afip.scopes.Scope
import afip.scopes.ScopeNotFoundException
import afip.variables.CollectionEntry
import afip.variables.CollectionVariable
import afip.variables.NormalVariable
import afip.variables.Variable
import afip.vulns.PathTraversal
import afip.vulns.RemoteCodeExecution
import afip.vulns.Vuln
import afip.vulns.XmlExternalEntitiesAttack
import org.apache.commons.logging.LogFactory
import org.codehaus.groovy.ast.ASTNode
import org.codehaus.groovy.ast.expr.*
/**
 * This class represent the basic functions to be able to process variables
 * , adding or removing taint as deemed fit.
 * This class does not assume parameter variables tainted
 * and does not have information of the methods in the repository.
 * A tainter must have a collection of vulnerabilities which taints variables with,
 * alongside with a cleaners object which specifies which cleaners are already
 * registered.
 *
 * The tainter will also add new cleaners as it performs its analysis!
 */
class MethodTainter {

    static final log = LogFactory.getLog(this)
    Collection<Class<? extends Vuln>> vulns
    Variable variableBeingAnalized
    MethodAnalyzer analyzer
    Project project

    /*
    TaintCarrier are objects which "carry" taint
    For example, you can create a ProcessBuilder quite alright
    def proc = new ProcessBuilder(params.foo)
    and now proc must be tainted of course.
    Constructors are a special case because generally
    we do not consider foo as tainted when doing something like
    def foo = new Foo(params.something)
    */
    HashMap<String, Class<? extends Vuln>> taintCarriers = [
            'ProcessBuilder': RemoteCodeExecution,
            'File': PathTraversal,
    ]

    /*
    Absolute dangers are classes which should be tainted
    even if no tainted value reaches them.
     */
    HashMap<String, Class<? extends Vuln>> absoluteDangers = [
            'XmlSlurper': XmlExternalEntitiesAttack,
    ]

    MethodTainter(Collection<Class<? extends Vuln>> vulns,MethodAnalyzer analyzer){
        this.vulns = vulns
        this.analyzer = analyzer
        this.project = analyzer.getProject()
    }

    Collection<Class<? extends Vuln>> getVulns(){
        return vulns.clone()
    }

    Variable getVariableBeingAnalized(){
        return variableBeingAnalized
    }

    void setVariableBeingAnalized(Variable var){
        variableBeingAnalized = var
    }

    HashMap<String, Class<? extends Vuln>> getAbsoluteDangers(){
        return absoluteDangers.clone()
    }

    HashMap<String, Class<? extends Vuln>> getTaintCarriers(){
        return taintCarriers.clone()
    }

    /**
     * Warning: recursive.
     * @param binaryExpression
     * @return: an array list of all the vulnerabilities this binary expression can trigger
     */
    protected ArrayList<Class<Vuln>> isDangerousFor(BinaryExpression binaryExpression) {
        Expression leftSide = binaryExpression.getLeftExpression()
        Expression rightSide = binaryExpression.getRightExpression()

        return isDangerousFor(leftSide) + isDangerousFor(rightSide)
    }

    /**
     * Warning: recursive
     * @return: an array list of all the vulnerabilities this mapExpression can trigger
     */
    protected ArrayList<Class<Vuln>> isDangerousFor(MapExpression mapExpression) {
        ArrayList<Class<Vuln>> dangerousFor = []
        for (MapEntryExpression mapEntryExpression : mapExpression.getMapEntryExpressions()) {
            def vulns = isDangerousFor(mapEntryExpression)
            dangerousFor.addAll(vulns)
        }
        return dangerousFor
    }
    /**
     * Warning: recursive
     * @return: an array list of all the vulnerabilities this gString
     */
    protected ArrayList<Class<Vuln>> isDangerousFor(GStringExpression gStringExpression) {
        ArrayList<Class<Vuln>> dangerousFor = new ArrayList<>()
        for (Expression property : gStringExpression.getProperties()['values']) {
            dangerousFor.addAll(isDangerousFor(property))
        }
        return dangerousFor
    }
    /**
     * Warning: recursive.
     * @param mapEntryExpression
     * @return: an array list of all the vulnerabilities this collection entry can trigger
     */
    protected ArrayList<Class<Vuln>> isDangerousFor(MapEntryExpression mapEntryExpression) {
        Expression value = mapEntryExpression.getValueExpression()
        return isDangerousFor(value)
    }
    /**
     * @param variableExpression
     * @return: an array list of all the vulnerabilities this variable expression can trigger
     */
    protected ArrayList<Class<Vuln>> isDangerousFor(VariableExpression variableExpression) {
        if (variableExpression.getName() == "params" || variableExpression.getName() == 'request') {
            return vulns.clone() as ArrayList<Class<Vuln>>
        }

        Variable rightSideVar
        Scope relevantScope = getVariableBeingAnalized().getScope()
        try {
            rightSideVar = relevantScope.getVariableOfName(variableExpression.getName())
        } catch (VariableNotFound ignored) {
            // this should indicate a variable that isn't defined by the programmer but used still.
            // we would care about this case if we were running a debugging tool. alas, that is not the case
            return []
        }
        return rightSideVar.getAllTriggerableVulns().asList()
    }

    /**
     * Warning: recursive.
     * @param propertyExpression
     * @return: an array list of all the vulnerabilities this property can trigger
     */
    protected ArrayList<Class<Vuln>> isDangerousFor(PropertyExpression propertyExpression) {
        return isDangerousFor(propertyExpression.getObjectExpression())
    }

    /**
     * Warning: recursive.
     * @param propertyExpression
     * @return: an array list of all the vulnerabilities this tuple expression can trigger
     */
    protected ArrayList<Class<Vuln>> isDangerousFor(TupleExpression tupleExpression) {
        ArrayList<Class<Vuln>> dangerousFor = new ArrayList<>()
        for (Expression node : tupleExpression.getExpressions()) {
            ArrayList<Class<Vuln>> danger = isDangerousFor(node)
            dangerousFor.addAll(danger)
        }
        return dangerousFor
    }

    /**
     * @param propertyExpression
     * @return: an array list of all the vulnerabilities this method call can trigger
     */
    protected ArrayList<Class<Vuln>> isDangerousFor(MethodCallExpression methodCallExpression) {
        def methodName = methodCallExpression.getMethodAsString()
        def receiver = methodCallExpression.getObjectExpression().getText()
        def project = getProject()
        def triggerables
        try {
            def method
            if (receiver == "this") {
                method = getAnalyzer().getActiveMethod().getClassScope().getMethodOfName(methodName)
            } else {
                method = project.getServiceOfName(receiver.capitalize()).getMethodOfName(methodName)
            }
            if (!method.isAnalyzed()) {
                try {
                    getAnalyzer().analyzeMethod(method)
                } catch (CircularAnalysisException ignored) { }
            }
            //LOGICA: vulns = arguments^menacesFor + sourceOf - cleanerOf
            triggerables = isDangerousFor(methodCallExpression.getArguments()).intersect(method.getMenaceOf()) + method.getSourceOf()
            triggerables = triggerables.unique() - method.getCleanerOf()
        } catch (ScopeNotFoundException ignored){
            triggerables = isDangerousAsReceiverAndParameters(methodCallExpression)
        }
        for (def vuln : getAnalyzer().getDetectorManager().getActiveVulns() ){
            if(getAnalyzer().getDetectorManager().getKnownCleaners().get(vuln).contains(methodName)){
                triggerables.remove(vuln)
            }
        }
        triggerables
    }

    Collection<Class<Vuln>> isDangerousAsReceiverAndParameters(MethodCallExpression methodCallExpression) {
        isDangerousFor(methodCallExpression.getArguments()) + isDangerousFor(methodCallExpression.getObjectExpression())
    }

    /**
     * Inspect constructor calls.
     * @param constructorCallExpression
     * @return: an array list of all the vulnerabilities the constructor may trigger.
     */
    protected ArrayList<Class<Vuln>> isDangerousFor(ConstructorCallExpression constructorCallExpression) {
        if (getTaintCarriers().containsKey(constructorCallExpression.getType().getText())) {
            if (isDangerousFor(constructorCallExpression.getArguments())) {
                return [getTaintCarriers()[constructorCallExpression.getType().getText()]]
            }
        }
        if (getAbsoluteDangers().containsKey(constructorCallExpression.getType().getText())) {
            return [getAbsoluteDangers()[constructorCallExpression.getType().getText()]]
        }
        return  []
    }

    /**
     * @param node
     * @return: an array list of all the vulnerabilities this node can trigger.
     */
    protected ArrayList<Class<Vuln>> isDangerousFor(ASTNode node) {
        return []
    }

    /**
     * @param Variable : a variable of any kind
     * @return: an array list of all the vulnerabilities this variable can trigger.
     */
    protected ArrayList<Class<Vuln>> isDangerousFor(Variable variable) {
        return isDangerousFor(variable.getValue())
    }

    /**
     * @param variable
     * @return whether the variable should be untainted or not.
     */
    boolean allBranchesUntainted(Variable variable, Class<Vuln> vulnClass) {
        Integer untaintedBranches = variable.getUntaintedBranchesFor(vulnClass)
        Integer allPossibleBranches = variable.getBranchesOnLastDeclaration()
        return untaintedBranches >= allPossibleBranches
    }

    /**
     * Should not be invoked for abstract class variable
     */
    void inspectVariable(Variable _){throw new Exception('method not yet implemented')}

    /**
     * Inspects the variable so as to know if we should taint, untaint or add an untainted branch.
     * If any vuln is found for the variable, it is added to the triggerable afip.vulns of the variable.
     * @param variable
     */
    @SuppressWarnings( "GroovyUnusedDeclaration" )
    void inspectVariable(NormalVariable variable) {
        setVariableBeingAnalized(variable)
        def previous = variable.getAllTriggerableVulns().toList()
        ArrayList<Class<Vuln>> variableTaintedFor = isDangerousFor(variable.getValue())
        variableTaintedFor.each { vuln -> variable.addTriggerableVuln(vuln) }
        List<Class<? extends Vuln>> variableSafeFor = previous - variableTaintedFor
        ArrayList<Class<Vuln>> variableUntaintedFor = []
        for (Class<? extends Vuln> vulnClass : variableSafeFor) {
            variable.addUntaintedBranchForVuln(vulnClass)
            if (allBranchesUntainted(variable, vulnClass)) {
                variableUntaintedFor.add(vulnClass)
                variable.removeTriggerableVuln(vulnClass)
            }
        }


        if (variable.getValue() instanceof VariableExpression) {
            def getterName = "get" + variable.getValue().getName().capitalize()
            def currentClass = getAnalyzer().getActiveMethod().getClassScope()
            def hasGetter = currentClass.hasMethodOfName(getterName)
            if (hasGetter) {
                def getter = currentClass.getMethodOfName(getterName)
                for (def vuln : getter.getSourceOf()) {
                    variable.addTriggerableVuln(vuln)
                }
            }
        }
    }

    /**
     * A method to manage taint in the ultra-special case of the
     * XXE vulnerability.
     * This is special because it needs a particular combination of
     * parameters to be cleaned.
     */
    private void handleSetFeatureMethodForXXE(CollectionVariable collection) {
        CollectionEntry firstParam = collection.getEntry("0")
        CollectionEntry secondParam = collection.getEntry("1")
        CollectionEntry receiver = collection.getEntry("receiver0")

        if (collection.getName() != 'setFeature') { return }
        if (!(firstParam && secondParam && receiver )) { return }

        // make sure ALL of the definitions of the first and second
        // parameters are correct
        Boolean correctFirstParam = false
        firstParam.getOriginalVariables().each {
            var ->  correctFirstParam = var.getValue().getText() == "http://xml.org/sax/features/external-general-entities"
        }
        Boolean correctSecondParam = false
        secondParam.getOriginalVariables().each {
            var ->  correctSecondParam = var.getValue().getText() == "false"
        }

        if (!correctFirstParam || !correctSecondParam) { return }

        Variable referencedObject = collection.getScope().safelyGetVariableOfName(receiver.getValue().getText())
        if (! (referencedObject && referencedObject instanceof NormalVariable)) { return }
        referencedObject.addUntaintedBranchForVuln(XmlExternalEntitiesAttack)
        if (allBranchesUntainted(referencedObject, XmlExternalEntitiesAttack)) {
            referencedObject.removeTriggerableVuln(XmlExternalEntitiesAttack)
        }
    }

    /**
     * Extract the entries from the collection variable and inspect them as normal variables.
     * @param collection: a collection variable
     */
    void inspectVariable(CollectionVariable collection) {
        setVariableBeingAnalized(collection)
        isDangerousFor(collection.getValue())
        handleSetFeatureMethodForXXE(collection)
        cleanCollectionIfPossible(collection)
        for (CollectionEntry entry : collection.getEntries().flatten()) {
            inspectVariable(entry.getVariable())
        }
    }

    void cleanCollectionIfPossible(CollectionVariable collection) {
        ArrayList<Class<? extends Vuln>> cleans = []
        if (getAnalyzer().getActiveMethod().getClassScope().hasMethodOfName(collection.getName())) {
            def method = getAnalyzer().getActiveMethod().getClassScope().getMethodOfName(collection.getName())

            if (!method.isAnalyzed()) {
                try {
                    getAnalyzer().analyzeMethod(method)
                } catch (CircularAnalysisException ignored) {}
            }
            cleans = getAnalyzer().getActiveMethod().getClassScope().getMethodOfName(collection.getName()).getCleanerOf().intersect(getAnalyzer().getDetectorManager().getActiveVulns())
        }
        def knownCleaners = getAnalyzer().getDetectorManager().getKnownCleaners()
        // if the cleaner does not take input screw it
        if (!collection.getEntry("0")) return
        def var = collection.getScope().safelyGetVariableOfName(collection.getEntry("0").getValue().getText())
        if (!(var instanceof NormalVariable)) return
        var = var as NormalVariable
        NormalVariable normalVariable= var as NormalVariable
        for(Class<? extends Vuln> vuln : cleans){
            if (knownCleaners.get(vuln).contains(collection.getName())) return
            if (collection.isConstructor()) return
            normalVariable.addUntaintedBranchForVuln(vuln)
            if (allBranchesUntainted(var, vuln)) {
                normalVariable.removeTriggerableVuln(vuln)
            }
        }
    }
}

