package afip.variables

import afip.scopes.Scope
import afip.vulns.Vuln
import org.codehaus.groovy.ast.expr.ConstantExpression
import org.codehaus.groovy.ast.expr.Expression
import org.codehaus.groovy.ast.expr.MapEntryExpression

/**
 * A minimal class to represent class entries.
 * @field key: an expression representing the key of the entry
 * @field value: an expression representing the value of the entry
 * @field isTainted: a Boolean indicating if this particular entry is tainted
 */
class CollectionEntry extends Variable implements Taintable {
    Expression key
    CollectionVariable collection
    Variable variable

    protected CollectionEntry(MapEntryExpression mapEntryExpression, CollectionVariable collection, Scope scope, Integer branches) {
        setFields(mapEntryExpression.getKeyExpression().getText(),
                mapEntryExpression.getValueExpression(),
                mapEntryExpression,
                scope,
                branches
        )
        this.collection = collection
        this.key = mapEntryExpression.getKeyExpression()
        this.name = this.name != 'loadFactor' ? this.name : 'loadFactorXXX'
        this.variable = createFake(this.name, this.value, scope, branches)
        this.collection._addEntry(this.name, this)
        this.originalNode = mapEntryExpression
    }

    protected CollectionEntry(Expression key, Expression value, CollectionVariable collection, Scope scope, Integer branches) {
        new CollectionEntry(new MapEntryExpression(key, value), collection, scope, branches)
    }

    protected CollectionEntry(Expression expression, CollectionVariable collection, Scope scope, Integer branches) {
        new CollectionEntry(new ConstantExpression(collection.getEntries().size()), expression, collection, scope, branches)
    }

    Variable getVariable() { return variable }


    HashSet<Class<Vuln>> getTriggerableVulns() {
        return getVariable().getTriggerableVulns()
    }

    ArrayList<CollectionEntry> getAllLivingDefinitions() {
        return this.getCollection().getAllCollectionValuesWithName(getName())
    }

    HashSet<Class<Vuln>> getAllTriggerableVulns() {
        HashSet<Class<Vuln>> allPossibleTriggerable = new HashSet<>()
        for (CollectionEntry collectionValue : getAllLivingDefinitions()) {
            allPossibleTriggerable.addAll(collectionValue.getTriggerableVulns())
        }
        return allPossibleTriggerable
    }

    /**
     * IMPORTANT PRECONDTION: only call if you are sure this variable is indeed a map somewhere
     * Better make sure there's a collection in there somewhere, cowboy. */
    HashSet<String> getKeysWhichTrigger(Class<Vuln> vulnClass) {
        ArrayList<Variable> vars = variable.isOriginal() ? [variable] : variable.getReferencedVariables()
        ArrayList<CollectionVariable> mapVars = vars.findAll { it instanceof CollectionVariable }
        HashSet<String> keys = new HashSet<>()
        mapVars.each { keys.addAll(it.getKeysWhichTrigger(vulnClass).asList()) }
        return keys
    }

    Boolean canTrigger(Class<Vuln> vulnType) {
        return getAllTriggerableVulns().contains(vulnType)
    }

    Boolean canThisBranchTrigger(Class<Vuln> vulnType) {
        return getTriggerableVulns().contains(vulnType)
    }

    void addTriggerableVuln(Class<Vuln> vulnType) {
        assert getVariable() instanceof Taintable
        (getVariable() as Taintable).addTriggerableVuln(vulnType)
    }

    void removeTriggerableVuln(Class<Vuln> vulnType) {
        assert getVariable() instanceof Taintable
        (getVariable() as Taintable).removeTriggerableVuln(vulnType)
    }

    void addUntaintedBranchForVuln(Class<Vuln> vulnClass) {
        assert getVariable() instanceof Taintable
        (getVariable() as Taintable).addUntaintedBranchForVuln(vulnClass)
    }

    Integer getUntaintedBranchesFor(Class<Vuln> vulnClass) {
        assert getVariable() instanceof Taintable
        (getVariable() as Taintable).getUntaintedBranchesFor(vulnClass)
    }
}
