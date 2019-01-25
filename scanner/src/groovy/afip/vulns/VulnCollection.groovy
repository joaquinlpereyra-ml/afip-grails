package afip.vulns

/**
 * A vuln collection is a simple assortments of vulnerabilities.
 * It has the capability to be converted to a JSON-ready array.
 */
class VulnCollection {
    HashMap<String, ArrayList<Vuln>> vulns

    /**
     * Init the vuln collection.
     */
    VulnCollection() {
        vulns = new HashMap<String, ArrayList<Vuln>>()
    }

    /**
     * Add a tag to organize vulnerabilities.
     * Generally, this is the git tag where the vulns were found.
     */
    void addTag(String tag, ArrayList<Vuln> vulns) {
        this.vulns[tag] = vulns
    }

    /**
     * Convert the collection to a JSON-ready array of vulnerabilities, compliant with the JSON API Spec.
     * The vulnerability list will look like this:
     * {
     *     [
     *          "type": "branch",
     *          "id": the tag,
     *          "attributes": [
     *              vuln1
     *              vuln2
     *              ...
     *          ],
     *          ...
     *     ]
     * }
     */
    ArrayList<Map<String, Object>> asJSONArray() {
        def asMap = vulns.collectEntries { branch, vlns -> [(branch): vlns.collect{it.toMap()}] }
        def asArray = []
        // for each key, value in asMap, add to asArray the map on the right
        asMap.each {k,v -> asArray << ['type':'branch','id':k,'attributes':v]}
        return asArray
    }
}
