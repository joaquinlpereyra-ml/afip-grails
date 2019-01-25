package afip.tainter

import afip.code.lines.LineClassifier
import afip.errors.CircularAnalysisException
import afip.main.MethodAnalyzer
import afip.scopes.ScopeNotFoundException
import afip.variables.NormalVariable
import afip.vulns.Vuln
import org.codehaus.groovy.ast.expr.MethodCallExpression

class PlaygroundMethodTainter extends MethodTainter {
    LineClassifier lineClassifier

    PlaygroundMethodTainter(Collection<Class<? extends Vuln>> vulns, MethodAnalyzer analyzer, LineClassifier lineClassifier) {
        super(vulns, analyzer)
        this.lineClassifier = lineClassifier
    }

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
            for (def vuln : method.getCleanerOf()){
                lineClassifier.addCleaner(variableBeingAnalized.getOriginalNode().getText(), variableBeingAnalized.getOriginalNode().getLineNumber())
            }
        } catch (ScopeNotFoundException ignored){
            triggerables = isDangerousAsReceiverAndParameters(methodCallExpression)
        }
        for (def vuln : getAnalyzer().getDetectorManager().getActiveVulns()){
            if(getAnalyzer().getDetectorManager().getKnownCleaners().get(vuln).contains(methodName)){
                lineClassifier.addCleaner(variableBeingAnalized.getOriginalNode().getText(), variableBeingAnalized.getOriginalNode().getLineNumber())
                triggerables.remove(vuln)
            }
        }
        triggerables
    }

    @SuppressWarnings("GroovyUnusedDeclaration")
    void inspectVariable(NormalVariable variable) {
        setVariableBeingAnalized(variable)
        ArrayList<Class<Vuln>> variableTaintedFor = isDangerousFor(variable.getValue())
        variableTaintedFor.each { vuln -> variable.addTriggerableVuln(vuln) }
        List<Class<? extends Vuln>> variableSafeFor = Vuln.getSubclasses() - variableTaintedFor
        ArrayList<Class<Vuln>> variableUntaintedFor = []
        for (Class<? extends Vuln> vulnClass : variableSafeFor) {
            variable.addUntaintedBranchForVuln(vulnClass)
            if (allBranchesUntainted(variable, vulnClass)) {
                variableUntaintedFor.add(vulnClass)
                variable.removeTriggerableVuln(vulnClass)
            }
        }


        def getterName = "get"+variable.getName().capitalize()
        def currentClass = getAnalyzer().getActiveMethod().getClassScope()
        def hasGetter = currentClass.hasMethodOfName(getterName)
        if (hasGetter) {
            def getter = currentClass.getMethodOfName(getterName)
            for (def vuln : getter.getSourceOf()) {
                variable.addTriggerableVuln(vuln)
            }
        }

        variableTaintedFor.collect {
            getLineClassifier().addTainted(variable.getOriginalNode().getText(), variable.getOriginalNode().getLineNumber())
        }

    }
}
