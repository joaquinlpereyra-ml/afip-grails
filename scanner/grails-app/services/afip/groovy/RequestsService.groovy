package afip.groovy

import afip.vulns.VulnCollection
import groovyx.net.http.ContentType
import groovyx.net.http.HTTPBuilder
import groovyx.net.http.Method
import groovyx.net.http.URIBuilder
import org.apache.http.conn.HttpHostConnectException

class RequestsService {
    static transactional = false
    def middlewareURI = _getMiddlewareURI()
	def relativePath = _getRelativePath()
	
	def _getMiddlewareURI(){
		def scope = System.getenv("SCOPE")
        def url
        switch (scope) {
            case "docker":
                url = 'http://example-api:8000'
                break
            default:
                url = 'http://localhost:8000'
        }
        log.info(["title": "set up middleware url", "url": url, "scope": scope])
        return url
	}
	
    // alex + nikito are probably the best two programmers in the world
	def _getRelativePath(){
		def scope = System.getenv("SCOPE")
		def path
		switch (scope) {
			case "test":
				path = '/test_afip'
				break
			case "nice":
				path = '/afip'
				break
			default:
				path = ''
		}
		log.info(["title": "set up relative path", "path": path, "scope": scope])
		return path
	}

    def getQueue(Closure callback) {
        def http = new HTTPBuilder(middlewareURI)
        http.handler.failure = { resp ->
            log.error(["title": "error requesting queue", "status": resp.statusLine.statusCode])
        }

        try {
            http.request(Method.GET, ContentType.JSON) {
                uri.path = relativePath + '/scans/queue'

                response.success = { resp, json ->
                    log.debug(['title': "got queue"])
                    callback(json)
                }
            }
        } catch (HttpHostConnectException e) {
            log.error(['title': 'Connection to middleware failed', 'error': e.toString()])
        }
    }

    def commit(String commitURL, String scanID) {
        log.debug(["title": "committing scan", "commitURL": commitURL, "scanID": scanID])
        put(commitURL, [:])
    }

    def postResults(String url, VulnCollection vulns, String scanHash) {
        def metadata = generateMetadata(scanHash)
        def vulnsJSON = vulns.asJSONArray()
        def compliantBody = ['data':vulnsJSON, 'meta': metadata]
        post(url, compliantBody)
    }

    def postError(String url, ArrayList error, String scanHash) {
        def metadata = generateMetadata(scanHash)
        def compliantBody = ['errors': error, 'meta': metadata]
        post(url, compliantBody)
    }

    def private static generateMetadata(String scanHash) {
        def version = System.getenv('VERSION') ?: 'local'
        return ['hash': scanHash, 'language': 'groovy', 'version': version]
    }

    /** Return True if a test can be posted to urlToTest, False otherwise */
    def testPost(String urlToTest) {
        if (! urlToTest ) { return false }
        def success = false
        try { post(urlToTest, ['data': [['type': 'test']]], { success = true }, {}) } catch (IOException) { }
        return success
    }

    /** * Post postBody to URL as a JSON. You can define closures to be called when the request either success or fails.*/
    def post(String URL, Map postBody, Closure onSuccess = {}, Closure onFail = {}) {
        request(Method.POST, URL, postBody, onSuccess, onFail)
    }

    /** * Put postBody to URL as a JSON. You can define closures to be called when the request either success or fails.*/
    def put(String URL, Map body, Closure onSuccess = {}, Closure onFail = {}) {
        request(Method.PUT, URL, body, onSuccess, onFail)
    }

    /** Request with METHOD to the URL with the specified body. Accepts closures to define what happens on success or failure */
    def private request(Method method, String URL, Map postBody, Closure onSuccess = {}, Closure onFail = {}) {
        log.info(["title": "posting to callback", "url": URL, "json": postBody])
        // WARNING: HTTPBuilder is very special. Do not touch unless you know what you're doing
        // or are in the mood for sufferi
        def obj_url = new URIBuilder(URL)
        def http = new HTTPBuilder(obj_url)
        http.request (method, ContentType.JSON ) {
            uri.path = obj_url.path
            body = postBody
            response.success = onSuccess
            response.fail = onFail
        }
    }
}
