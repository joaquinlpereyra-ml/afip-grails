package afip.main

import afip.code.lines.LineClassifier
import afip.errors.CircularAnalysisException
import afip.managers.DetectorManager
import afip.scopes.*
import afip.tainter.MethodTainter
import afip.tainter.ParanoidMethodTainter
import afip.tainter.PlaygroundMethodTainter
import afip.variables.Variable
import afip.vulns.Vuln
/** * A method analyzer will inspect methods inside a project. */
class MethodAnalyzer {

    Project project
    List<Method> methodStack
    Method activeMethod
    DetectorManager detectorManager

    /**
     * @param project: the project the methods live on
     * @param detectorManager: the connection to our detectors
     */
    MethodAnalyzer(Project project, DetectorManager detectorManager) {
        this.detectorManager = detectorManager
        this.project = project
        this.methodStack = []
    }

    /**
     * Will find vulns inside a method
     * It will use a method tainter to perform
     * taint analysis on the methods and the methods
     * which this methods calls!
     */
    List<Vuln> findVulns(Method m) {
        if(!m.isAnalyzed()) {
            analyzeMethod(m)
        }
        activeMethod = m
        def tainter =  new MethodTainter(detectorManager.getActiveVulns(),this)
        recursiveTaintAnalysisWith(tainter,[m])
        def vulns = recursiveFindVulns([m])
        vulns

    }

    /**
     * Performs soul-searching analysis on a method.
     *
     *     What am I?, says the method.
     *     You are a cleaner, says the method which analyzes the method.
     *     And I?, says another method.
     *     You are a source, says the method which analyzes the method.
     *     And so the first method cleaned its brother of its impurities.
     *
     * It will try to find out if a method is a source, sink, menace or cleaner.
     * @throws afip.errors.CircularAnalysisException:
     *     when Foo called Bar and Bar called Foo :)
     *     in short, we don't support recursion nor mutual recursion
     */
    void analyzeMethod(Method method) throws CircularAnalysisException {
        if(getMethodStack().contains(method)){
            activeMethod.markAsAnalyzed()
            throw new CircularAnalysisException()
        }
        activeMethod = method
        methodStack.push(method)
        findIfSourceOrMenaceOfVulns()
        findIfSinkOrCleanerOfVulns()
        def top = methodStack.pop()
        if(top) activeMethod = top
        method.markAsAnalyzed()

        // variables must be reset afterwards, so as not to
        // change results for other variables until all
        // calls have been analyzed
        resetVariables()
    }

    /**
     * Provided with a tainter and a list of scopes, it will inspect
     * the variables inside each of the scopes.
     * Inspecting the variables consist mainly on marking them as tainted
     * if need be.
     */
    void recursiveTaintAnalysisWith(MethodTainter tainter, List<Scope> scopes) {
        for (Scope scope : scopes ) {
            for (Variable var : scope.getReferecedVariables()) {
                tainter.inspectVariable(var)
            }
            recursiveTaintAnalysisWith(tainter,scope.getInnerScopes())
        }
    }

    /**
     * Provided with a list of scopes, it will pass the detectors
     * to each of the scopes and its inner scopes
     */
    ArrayList<Vuln> recursiveFindVulns(List<Scope> scopes) {
        ArrayList<Vuln> vulns = []
        for (Scope scope : scopes) {
            for (Variable var : scope.getScopeVariables()) {
                vulns.addAll(detectorManager.detect(var))
            }
            ArrayList<Vuln> innerVulns = recursiveFindVulns(scope.getInnerScopes())
            if (innerVulns) { vulns.addAll(innerVulns) }
        }
        return vulns
    }

    /**
     *  findsSinks tries to find vulnerabilities assuming everything parameter tainted. Methods which were found to have
     *  vulnerabilities are considered as knownSinks.
     */
    void findIfSinkOrCleanerOfVulns(){
        resetVariables()
        def paranoid = new ParanoidMethodTainter(detectorManager.getActiveVulns(),this)
        def scope = getActiveMethod()
        recursiveTaintAnalysisWith(paranoid, [scope])
        checkIfCleaner(scope)
        recursiveFindVulns([scope]).each {vuln ->
            scope.addSinkOf(vuln.getClass() as Class<Vuln>)
        }
    }

    /** * Will tell if a scope if a cleaner or not. */
    private void checkIfCleaner(Method scope) {
        if (!(scope.hasReturnVariable())) return
        def returns = scope.getVariableOfName("return")
        def vulns = Vuln.getSubclasses()
        def taintReturnedInVulns = returns.getAllTriggerableVulns()
        def cleaned = vulns - taintReturnedInVulns
        for (Class<? extends Vuln> clean : cleaned){
            scope.addCleanerOf(clean)
        }
    }

    /**
     *  findsMenaces tries to find methods which return taint assuming
     *  every parameter tainted and does not return taint
     *  when parameters are not tainted.
     */
    void findIfSourceOrMenaceOfVulns(){
        resetVariables()

        def method =  getActiveMethod()
        if (!method.hasReturnVariable()) return
        def tainter = new MethodTainter(detectorManager.getActiveVulns(),this)
        def paranoid = new ParanoidMethodTainter(detectorManager.getActiveVulns(),this)
        recursiveTaintAnalysisWith(tainter, [method])

        def taintedFor = method.getVariableOfName("return").getAllTriggerableVulns()
        def notTaintedForMethodTainter = Vuln.getSubclasses() - taintedFor

        taintedFor.each {vuln -> method.addSourceOf(vuln)}

        resetVariables()
        recursiveTaintAnalysisWith(paranoid, [method])
        def taintedForParnoidTainter = method.getVariableOfName("return").getAllTriggerableVulns()

        for (Class<? extends Vuln> vuln : notTaintedForMethodTainter.intersect(taintedForParnoidTainter)){
            method.addMenaceOf(vuln)
        }
    }

    /** Applies reset function to every variable in every scope **/
    void resetVariables(){
        getActiveMethod().traverse({ Scope scope ->
            scope.getVariables().values().each {
                it.each {it.reset()}
            }
        })
    }

    ArrayList<Vuln> analyzeService(Service service) {
        ArrayList<Vuln> vulns = new ArrayList<>()
        for (Method method : service.getMethods()) {
            vulns.addAll(findVulns(method))
        }
        return vulns
    }

    ArrayList<Vuln> analyzeConfig(Config config) {
        findVulns(config.getMethodOfName("run"))
    }

    ArrayList<Vuln> analyzeDatabaseFile(DatabaseFile databaseFile) {
        findVulns(databaseFile.getMethodOfName("run"))
    }

    /**
     * Starts analysis for the playground..
     * @param lineClassifier: it uses this to classify each line of the method
     * @return
     */
    ArrayList<Vuln> playgroundAnalysis(LineClassifier lineClassifier, Method method) {
        if(!method.isAnalyzed()) {
            analyzeMethod(method)
        }
        activeMethod = method
        def pgt = new PlaygroundMethodTainter(detectorManager.getActiveVulns(),this,lineClassifier)
        recursiveTaintAnalysisWith(pgt,[method])
        def vulns = recursiveFindVulns([method])
        vulns.each {lineClassifier.addVulnerable(it.getCode(),it.getLineNumber())}
        vulns
    }
}
