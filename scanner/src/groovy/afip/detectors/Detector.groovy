package afip.detectors

import afip.scopes.Project
import afip.scopes.Scope
import afip.variables.Variable
import afip.vulns.Vuln

abstract class Detector {
    Class<? extends Vuln> detects
    HashSet<String> defaultSinks = new HashSet<>()
    Boolean on
    String filePath
    Project project
    HashSet<String> defaultCleaners = new HashSet<>()

    /**
     * Create a detector for a given vulnerability.
     * @param vulnerabilityItDetects: the vulnerability this detects
     * @param defaultSinks: a variadic list of strings which represent the
     *                      known knownSinks for a detector
     */
    Detector(Class<? extends Vuln> vulnerabilityItDetects,
             List<String> defaultSinks,
             List<String> defaultCleaners) {
        detects = vulnerabilityItDetects
        this.defaultCleaners.addAll(defaultCleaners)
        this.defaultSinks.addAll(defaultSinks)
        turnOff()
    }

    void turnOn() { on = true }

    void turnOff() { on = false }

    /**
     * Sets the path of the file being analized.
     * You most probably can leave it as is.
     */
    void setFilePath(String filePath) {
        this.filePath = filePath
    }

    void setProject(Project project) {
        this.project = project
    }

    Boolean isOn(){
        return on
    }

    Boolean isSink(String receiver, String sink, Scope scope) {
        defaultSinks.contains(sink) || project.isDynamicSink(receiver, sink, scope, this.getVuln())
    }

    /**
     * Does nothing by default.
     * Can be overriden by subclasses to set
     * the view files, if needed.
     */
    void setViewFiles(ArrayList<File> viewFiles) { }

    /**
     * Does nothing by default.
     * Can be overriden by subclasses to set
     * the views folder, if needed.
     * @param viewFolder
     */
    void setViewsFolder(File viewFolder) { }

    /**
     * Will be called for every variable on the program.
     * You need to implement this in your subclass
     * to make the detector useful.
     */
    ArrayList<Vuln> detect(Variable variable) {
        return new ArrayList<Vuln>()
    }


    /**
     * Returns the vulnerability this detector detects.
     * @return
     */
    Class<? extends Vuln> getVuln() {
        return this.detects
    }

}

