package afip.groovy

import afip.errors.NotValidRepository
import afip.main.Scanner
import org.codehaus.groovy.runtime.powerassert.PowerAssertionError

class AfipService {
    static transactional = false
    def busy = false
    def requestsService
    def isBusy() {
        return busy
    }

    def errorTypes = [
            'FJV': "FailedJsonValidations",
            'FPV': "FailedPreconditionValidations",
            'FAC': "FailedAddressCommit",
            'WCB': "WrongCallback",
            'NGR': "NotAGrailsRepository",
            'NVR': "NotValidRepository",
            'RE': "RuntimeException"
    ]

    def startScan(Map<String, Object> json) {
        if (isBusy()) { return }
        String postAddress = json.get('meta').get('callback')
        def failedJSONValidations = validateJSON(json)
        if (failedJSONValidations) {
            def error = ['title': errorTypes['FJV'], "detail": failedJSONValidations.join('&&')]
            log.warn(['error': error])
            return requestsService.postError(postAddress, [error], json.get('data').get('id'))
        }
        def queue = json.get('data')?.get('attributes')?.get('groovy')
        if (!queue) return

        def scan = queue.get(0)
        def scanAttrs = scan.get('attributes')
        log.info(['title': 'received scan', 'id': scan.get('id'), "scan": scan])
        Boolean disablePostTest = json.get('meta').get('disableTestProbe')
        String scanHash = scan.get('id')
        String repoURL = scanAttrs.get('repositoryURL')
        ArrayList<String> tags = scanAttrs.get('tags')
        ArrayList<String> detectors = scanAttrs.get('detectors') ?: []
        String commitAddress = scanAttrs.get('commitURL')

        def failedValidations = validateRequest(repoURL, postAddress, disablePostTest)
        if (failedValidations) {
            def log_error = ['title': errorTypes['FPV'], "detail": failedValidations]
            log.warn(['error': log_error])
            return requestsService.postError(postAddress, failedValidations, scan.get('id'))
        }

        try {
            log.info(["title": "accepted scan", "json": json])
            requestsService.commit(commitAddress, scanHash)
        } catch (Exception e) {
            log.warn(['error': e])
            def error = ['title': errorTypes['FAC'], 'detail': e.getMessage()]
            return requestsService.postError(postAddress, [error], scan.get('id'))
        }
        return triggerScan(repoURL, postAddress, detectors, scanHash, tags)
    }

    private validateJSON(Map<String, Object> json) {
        String noCallback = "The response must provide a callback to post the results!"
        String noGroovyQueue = "The response must include a queue for the groovy language"
        ArrayList failed = []
        if (json.get('data')?.get('attributes')?.get('groovy') == null ) { failed.add("noGroovyQueue": noGroovyQueue) }
        if (! (json.get('meta')?.get('callback'))) { failed.add("NoCallback": noCallback) }
        return failed
    }

    private validateRequest(String repoUrl, String postAddress, Boolean disablePostTest) {
        String badRepoMsg = 'Repo URL must start with "https://github.com/". Note no www involved.'
        String badCallbackMsg = 'Supply a valid callback address to post to'
        ArrayList failed = []
        if (! repoUrl?.startsWith("https://github.com")) {
            failed.add(['title': errorTypes['NVR'], 'detail': badRepoMsg])
        }
        if (! disablePostTest && ! requestsService.testPost(postAddress)) {
            failed.add(['title': errorTypes['WCB'], 'detail': badCallbackMsg])
        }
        return failed
    }

    private triggerScan(String repoUrl, String postAddress, ArrayList<String> detectors, String scanHash, ArrayList<String> branches) {
        log.info(["title": "starting scan", "repo": repoUrl, "postAddress": postAddress, "hash": scanHash, "detectors": detectors, "tags":branches])
        try {
            busy = true
            def scanner = Scanner.NewRepositoryScanner(scanHash)
            def vulns = scanner.scan(repoUrl, branches)
            requestsService.postResults(postAddress, vulns, scanHash)
        } catch (NotValidRepository e) {
            dealWithNotValidRepo(postAddress, e, scanHash)
        } catch (Throwable t) {
            dealWithRuntimeException(postAddress, t, scanHash)
            t.printStackTrace()
        } finally {
            busy = false
        }
    }

    private dealWithNotValidRepo(String postAddress, Throwable t, String scanHash) {
        def errorName = t.getClass().getSimpleName()
        def errorMessage = t.getMessage()
        def errorMap = ['title': errorName, 'detail': errorMessage]
        ArrayList<Map<String, String>> errorList = new ArrayList<>()
        errorList.add(errorMap)
        return requestsService.postError(postAddress, errorList, scanHash)
    }

    private dealWithRuntimeException(String postAddress, Throwable t, String scanHash) {
        log.error(["title": "runtime exception", "error": t.getClass().getSimpleName(), "stacktrace": t.getStackTrace()])
        def errorName = t.getClass().getSimpleName()
        def errorMessage = t.getMessage()

        // avoid leaking information about the inner state of the program
        if (t instanceof PowerAssertionError) { errorMessage = errorMessage.split('\n')[0] }

        def errorDetail = errorName + ' - ' + errorMessage
        def errorMap = ['title': errorTypes['RE'], 'detail': errorDetail]
        ArrayList<Map<String, String>> errorList = new ArrayList<>()
        errorList.add(errorMap)
        return requestsService.postError(postAddress, errorList, scanHash)
    }
}
