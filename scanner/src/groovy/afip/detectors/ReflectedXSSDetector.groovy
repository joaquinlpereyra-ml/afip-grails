package afip.detectors

import afip.files.GSPFile
import afip.files.Repository
import afip.variables.CollectionEntry
import afip.variables.CollectionVariable
import afip.variables.Variable
import afip.vulns.ReflectedXss
import org.apache.commons.logging.LogFactory
import org.codehaus.groovy.ast.expr.Expression
/**
 * Responsible for detecting Reflected Cross-site Scripting vulnerabilities.
 */
class ReflectedXSSDetector extends Detector {
    private static final log = LogFactory.getLog(this)
    File viewsFolder

    /** Fields should be set before calling the detect method! */
    ReflectedXSSDetector() {
        super(ReflectedXss, ['render'], ['encodedAsHTML'])
    }

    void setViewsFolder(File viewsFolder) { this.viewsFolder = viewsFolder }

    /**
     * Detects XSSs on the methodCallExp.
     * It will use the information on the methodcall, and will search all the views for usage of the tainted
     * keys in case it renders a view with a model and we can find the view.
     * It will also take into account renders via the 'view' key and unsafe redirects.
     * @returns: a list with all the cross sites found.
     */
    @SuppressWarnings( "GroovyUnusedDeclaration" )
    ArrayList<ReflectedXss> detect(CollectionVariable methodCall) {
        log.debug(["title": "starting detection", "vuln": "reflected xss"])
        if (!on) return []
        ArrayList<ReflectedXss> XSSs = new ArrayList<>()
        CollectionEntry render = methodCall.getEntry('model') ?: methodCall.getEntry('text')
        // some mandatory conditions for a cross site to exist.
        // it's important the canThisBranchTrigger method is called last
        if (! filePath.endsWith("Controller.groovy")) { return [] }
        if (!isSink(methodCall.getEntry("receiver0")?.getName(), methodCall.getName(), methodCall.getScope())) { return [] }
        if (rendersNorModelNorText(methodCall) && rendersView(methodCall)) { return handleVulnerableView(methodCall) }
        if (rendersSafeContentType(methodCall)) { return [] }
        if (!(render && render.canThisBranchTrigger(ReflectedXss))) { return [] }
        XSSs.addAll(handleVulnerableModel(methodCall))
        XSSs.addAll(handleVulnerableText(methodCall))
        XSSs.addAll(handleVulnerableRedirect(methodCall))

        return XSSs
    }

    /** Return True if methodCall is rendering a static view */
    static private rendersStaticView(CollectionVariable methodCall) {
        return (methodCall.getEntry('view')) && rendersNorModelNorText(methodCall)
    }

    static private rendersSafeContentType(CollectionVariable methodCall) {
        ArrayList<String> safeContentTypes = ['application/javascript', 'application/json']
        return methodCall.getEntry('contentType')?.getValue()?.getText() in safeContentTypes
    }

    /** Return True if the method call doesn't have an entry for model nor an entry for text nor an entry for redirect */
    static private rendersNorModelNorText(CollectionVariable methodCall) {
        return ! (methodCall.getEntry('model') || methodCall.getEntry('text') || methodCall.getEntry('redirect'))
    }

    /** Return True if the method call has an entry for view */
    static private rendersView(CollectionVariable methodCall) {
        return (methodCall.getEntry('view'))
    }

    /** Return a list containing a xss if the dangerous method call has a redirect entry. Empty list otherwise */
    private ArrayList<ReflectedXss> handleVulnerableRedirect(CollectionVariable methodCall) {
        if (methodCall.getEntry('redirect')) { return [createXSS('redirect', methodCall.getNode())] }
        return []
    }

    /** Return a list containing a ReflectedXss if the dangerous methodCall has a 'model' entry.
     * If we inspect the methodCall correctly and find the view associated with the model, it will
     * return a ReflectedXss of type 'model' in case the tainted keys have been found on the view.
     * If something happened and we can't find the views or detect the specific tainted keys of the model,
     * it will return a ReflectedXss of type 'maybe'.
     * @param methodCall
     * @return
     */
    private ArrayList<ReflectedXss> handleVulnerableModel(CollectionVariable methodCall) {
        CollectionEntry model = methodCall.getEntry('model')
        if (! model) { return [] }

        log.debug("title": "vulnerable model in render", "methodCall": methodCall.getNode().getText())
        CollectionEntry view = methodCall.getEntry('view')
        String possibleViewPath = view ? view.getValue().getText() : ""
        ArrayList<File> possibleViews = possibleViewPath ? Repository.findAllViews(viewsFolder, possibleViewPath) : []
        ArrayList<String> taintedKeys = model.getKeysWhichTrigger(ReflectedXss)
        if (!possibleViews || !taintedKeys) {
            return noInformationFoundXSS(methodCall, possibleViews, taintedKeys, model, possibleViewPath)
        }

        for (File viewFile : possibleViews) {
            String viewPath = viewFile.getAbsolutePath()
            Boolean taintedUsedInView = new GSPFile(viewPath).findUsage(taintedKeys)
            if (taintedUsedInView) {
                return [createXSS('model', methodCall.getNode())]
            }
        }
        return []
    }

    /**
     * If we inspect the methodCall correctly and find the view associated with the model, it will
     * return a ReflectedXss of type 'view' in case 'params' are found in the view.
     * If something happened and we can't find the views or detect the use of 'params' in the view,
     * it will return a ReflectedXss of type 'maybe'.
     * @param methodCall
     * @return
     */
    private ArrayList<ReflectedXss> handleVulnerableView(CollectionVariable methodCall){

        log.debug("title": "vulnerable view in render", "methodCall": methodCall.getNode().getText())
        CollectionEntry view = methodCall.getEntry('view')
        String possibleViewPath = view ? view.getValue().getText() : ""
        ArrayList<File> possibleViews = possibleViewPath ? Repository.findAllViews(viewsFolder, possibleViewPath) : []
        for (File viewFile : possibleViews) {
            Boolean paramsUsedInView = new GSPFile(viewFile).findUsage(["params"])
            if (paramsUsedInView) {
                return [createXSS('view', methodCall.getNode())]
            }
        }
        return []
    }

    /** Return a list with the xss if the dangerous methodcall has a text entry. Empty list otherwise. */
    private ArrayList<ReflectedXss> handleVulnerableText(CollectionVariable methodCall) {
        methodCall.getEntry('text') ? [createXSS('text', methodCall.getNode())] : []
    }

    /** Simple helper function. Logs and then returns a list with a maybe xss associated with the methodCall */
    private ArrayList<ReflectedXss> noInformationFoundXSS(CollectionVariable methodCall, ArrayList<File> possibleViews,
                                                          ArrayList<String> taintedKeys, CollectionEntry model, String possibleViewPath) {
        return [createXSS('maybe', methodCall.getNode())]
    }

    /** Creates a xss object and return it. */
    private ReflectedXss createXSS(String type, Expression expression) {
        return new ReflectedXss(type, filePath, expression.getLineNumber(), expression.getText())
    }
}
