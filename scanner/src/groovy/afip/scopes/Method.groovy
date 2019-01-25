package afip.scopes

import afip.managers.BranchManager
import afip.visitors.MethodCanonizator
import afip.visitors.VariableCreator
import afip.vulns.Vuln
import org.codehaus.groovy.ast.MethodNode

class Method extends Scope{
    Boolean analyzed

    Set<Class<Vuln>> sourceOf
    Set<Class<Vuln>> menaceOf
    Set<Class<Vuln>> cleanerOf
    Set<Class<Vuln>> sinkOf

    Method(MethodNode node, ClassScope owner){
        super(node,owner)
        initializeSets()
        extractVariables()
    }

    private void initializeSets() {
        sourceOf = new HashSet<>()
        menaceOf = new HashSet<>()
        cleanerOf = new HashSet<>()
        sinkOf = new HashSet<>()
    }

    void addSourceOf(Class<Vuln> vuln){this.sourceOf.add(vuln)}
    void addCleanerOf(Class<Vuln> vuln){this.cleanerOf.add(vuln)}
    void addMenaceOf(Class<Vuln> vuln) { this.menaceOf.add(vuln) }

    void addSinkOf(Class<Vuln> vuln){ this.sinkOf.add(vuln) }


    Set<Class<Vuln>> getSourceOf(){sourceOf}
    Set<Class<Vuln>> getCleanerOf(){cleanerOf}
    Set<Class<Vuln>> getMenaceOf(){menaceOf}
    Set<Class<Vuln>> getSinkOf(){sinkOf}

    Boolean isSourceOf(Class<Vuln> v){sourceOf.contains(v)}
    Boolean isCleanerOf(Class<Vuln> v){cleanerOf.contains(v)}
    Boolean isMenaceOf(Class<Vuln> v){menaceOf.contains(v)}
    Boolean isSinkOf(Class<Vuln> v){sinkOf.contains(v)}
    /**
     * Precondition: all getterNodes and fields have been registered as global afip.variables
     * Postcondition: all afip.variables of the class have been registered
     */
    void extractVariables() {
        def methodCanonizator = new MethodCanonizator()
        methodCanonizator.visit([this.getNode() as MethodNode])
        VariableCreator variableCreator = new VariableCreator(this, new BranchManager())
        variableCreator.visitConstructorOrMethod(this.getNode() as MethodNode,false)
    }

    Boolean isAnalyzed(){
       analyzed
    }

    void markAsAnalyzed(){
        analyzed = true
    }

    ClassScope getClassScope(){
        outerScope
    }

}