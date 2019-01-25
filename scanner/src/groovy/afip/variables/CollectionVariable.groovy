package afip.variables

import afip.errors.UnknownSourceForVariable
import afip.scopes.Scope
import afip.utils.Ask
import afip.utils.Extract
import afip.vulns.Vuln
import org.codehaus.groovy.ast.expr.BinaryExpression
import org.codehaus.groovy.ast.expr.Expression
import org.codehaus.groovy.ast.expr.MapEntryExpression
import org.codehaus.groovy.ast.expr.MapExpression

/**
 * A class to represent maps and lists.
 * Lists are considered maps with keys of 0, 1, 2, 3... according to their index to the best of our knowledge.
 * Maps are more complicated regarding tainted, as they are basically holders for several afip.variables.
 * If one the entries of a collection is tainted, is the collection tainted? Who knows.
 * This class provides logic to answer such questions.
 */
class CollectionVariable extends Variable implements Dangerous {
    private HashMap<String, ArrayList<CollectionEntry>> collectionEntries

    /**
     * Given a collection declaration add the corresponding entries.
     * @precondition: the collection declaration is an actual declaration using the assignment operator
     * @param collectionDeclaration
     */
    private void createValuesFromCollectionDeclaration(BinaryExpression collectionDeclaration, Scope scope, Integer branches) {
        assert Ask.isUsingAssignmentOperator(collectionDeclaration)
        Expression collection = collectionDeclaration.getRightExpression()
        createValuesFromDeclaration(collection, scope, branches)
    }

    /**
     * Fill in the collection with the entries found in its declaration.
     */
    private void createValuesFromDeclaration(Expression collection, Scope scope, Integer branches) {
        assert Ask.isMapOrList(collection)
        ArrayList<Expression> entries = collection instanceof MapExpression ? collection.getMapEntryExpressions() : collection.getExpressions()
        for (Expression entry : entries){
            new CollectionEntry(entry, this, scope, branches)
        }
    }

    /**
     * Constructor.
     * @param collectionDeclaration
     * @param isLocal
     */
    protected CollectionVariable(BinaryExpression collectionDeclaration, Scope scope, Integer branches) {
        setFields(Extract.variableName(collectionDeclaration), collectionDeclaration.getRightExpression(), collectionDeclaration, scope, branches)
        this.collectionEntries = new HashMap<String, ArrayList<CollectionEntry>>()
        this.createValuesFromCollectionDeclaration(collectionDeclaration, scope, branches)
    }

    /** A variable reperesentation as a string. */
    String toString() {
        return super.toString() + "\n    " + this.getEntries().join("\n    ") + "\n"
    }

    /** Adds collection entries to the collection given a binary expression where there are entries being added to the collection
     * For example:
     * mapName['key'] = value,
     * or,
     * mapName << ['key': 'value']
     * or,
     * listName << "i am an element's list"
     * */
    void addEntry(BinaryExpression binaryExpression, Scope scope, Integer branches) throws UnknownSourceForVariable {
        Expression leftSide = binaryExpression.getLeftExpression()
        if (leftSide instanceof BinaryExpression) {
            Expression key = (leftSide as BinaryExpression).getRightExpression()
            Expression value = binaryExpression.getRightExpression()
            key = key != 'loadFactor' ? key : 'loadFactorXXX'
            new CollectionEntry(key, value, this, scope, branches)
        } else if (Ask.isNodeVariableMaterial(leftSide) && binaryExpression.getRightExpression() instanceof MapExpression) {
            MapExpression mapExpression = binaryExpression.getRightExpression() as MapExpression
            for (MapEntryExpression mapEntry : mapExpression.getMapEntryExpressions()) {
                new CollectionEntry(mapEntry, this, scope, branches)
            }
        } else if (Ask.isNodeVariableMaterial(leftSide) && binaryExpression.getRightExpression() instanceof Expression){
            Expression expression =  binaryExpression.getRightExpression() as Expression
            new CollectionEntry(expression, this, scope, branches)
        } else {
            throw new UnknownSourceForVariable()
        }
    }

    /** Adds an entry to the collection.
     * Remember! Upon creation, MapKeyValues are registered on this collection via this method, so no need to call it again.
     * @param key
     * @param mapEntry
     */
    void _addEntry(String key, CollectionEntry mapEntry) {
        if (! collectionEntries.containsKey(key) ) {
            collectionEntries[key] = new ArrayList<CollectionEntry>()
        }
        collectionEntries[key].add(mapEntry)
    }

    /** Return the entries inside this collection variables */
    ArrayList<ArrayList<CollectionEntry>> getEntries() { return collectionEntries.values() }

    /** Return how many entries are inside this collection variable */
    Integer size() { collectionEntries.size() }

    /** Return all the entries which are tainted inside this (AND ONLY THIS) collection variable */
    HashSet<Class<Vuln>> getTriggerableVulns() {
        HashSet<Class<Vuln>> triggerableVulns = new HashSet<>()
        for (CollectionEntry collectionValue : getEntries().flatten()) {
            triggerableVulns.addAll(collectionValue.getTriggerableVulns())
        }
        return triggerableVulns
    }

    /**
     * Return all the entries which are tainted inside this and all the possible branched instances of
     * this collection variable
     */
    HashSet<Class<Vuln>> getAllTriggerableVulns() {
        HashSet<Class<Vuln>> triggerableVulns = new HashSet<>()
        for (Variable variable : getAllLivingDefinitions()) {
            triggerableVulns.addAll(variable.getTriggerableVulns())
        }
        return triggerableVulns.flatten()
    }

    /**
     * Return all the entries which have name keyName inside this or all the possible branched instances of
     * this collection variable which are CollectionVariables themselves.
     * @param keyName: the name to search for
     * @return
     */
    ArrayList<CollectionEntry> getAllCollectionValuesWithName(String keyName) {
        ArrayList<CollectionEntry> mapKeyValues = new ArrayList<>()
        ArrayList<CollectionVariable> variables = getAllLivingDefinitions()

        for (Variable variable : variables) {
            if (!(variable instanceof CollectionVariable)) { continue }
            CollectionVariable mapVariable = variable as CollectionVariable
            for (CollectionEntry mapKeyValue : mapVariable.getEntries().flatten()) {
                if (mapKeyValue.getName() == keyName) {
                    mapKeyValues.add(mapKeyValue)
                }
            }
        }
        return mapKeyValues
    }

    /** Can this variable trigger the vulnerability represented by the vulnClass param? */
    Boolean canTrigger(Class<Vuln> vulnClass) {
        return getAllTriggerableVulns().contains(vulnClass)
    }

    /**
     * WARNING: may return null.
     * Return the firstly found instance of the entry of name 'key' if found, else null.
     */
    CollectionEntry getEntry(String key) { return collectionEntries[key] ? collectionEntries[key].get(0) : null }

    /**
     * Return all the keys which trigger the vulnerability represented by vulnClass on this or any of the
     * branched instances of this variable.
     */
    HashSet<String> getKeysWhichTrigger(Class<Vuln> vulnClass) {
        HashSet<String> dangerousKeys = new ArrayList<>()
        ArrayList<CollectionVariable> allMapVariables = getAllLivingDefinitions()

        for (Variable var : allMapVariables) {
            if (! (var instanceof CollectionVariable)) { continue }

            CollectionVariable mapVariable = var as CollectionVariable
            for (CollectionEntry mapKeyValue : mapVariable.getEntries().flatten()) {
                if (mapKeyValue.canTrigger(vulnClass)) {
                    dangerousKeys.add(mapKeyValue.getName())
                }
            }
        }
        return dangerousKeys
    }

    void reset() {
        for (CollectionEntry var : getEntries().flatten()) {
            var.getVariable().reset()
        }
    }

}
