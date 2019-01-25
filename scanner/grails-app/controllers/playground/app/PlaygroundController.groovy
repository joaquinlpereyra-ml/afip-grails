package playground.app

import afip.main.Scanner
import org.codehaus.groovy.grails.web.json.JSONObject

import static grails.async.Promises.task

class PlaygroundController {
    def requestsService

    def snippetAnalyser() {

        def json = request.JSON
        def failedValidation = validateJSON(json)
        if (failedValidation) {
            render(status: 400, contentType: "application/json") {
                [type: "invalid-json", attributes: failedValidation]
            }
            return
        }

        String ID = json.get("data").get("id")
        String vuln = json.get("data").get("attributes").get("vuln")
        String code = json.get("data").get("attributes").get("code")
        String url = json.get("data").get("attributes").get("url")

        log.info(["title": "Request snippet scan for Playground", "id": ID, "vuln": vuln , "url": url])

        render(status: 201, contentType: "application/json"){
            [type: "snippet-accepted", id: ID, attributes: [vuln: vuln]]
        }

        try {
            ArrayList<String> vulns = [vuln]
            def classifiedLines = Scanner.NewSnippetScanner(code, vulns, ID).scan()
            requestsService.post(url,[type: 'results', id: ID, attributes: [vuln: vuln, lines: classifiedLines ] ])
        }
        catch (Throwable t) {
            log.info("error": t.getStackTrace())
            requestsService.post(url,[type: 'failed-scan', id: ID])
        }
    }

    private validateJSON(JSONObject json){
        ArrayList validation = []
        if( json.get("data")?.get("id") == null ) {
            validation.add("nullID": "The ID received is null")
        } else {
            def validID = validateID( json.get("data").get("id") )
            if ( !validID ){
                validation.add("wrongID": "The ID received is not valid")
            }
        }
        if( json.get("data")?.get("type") != "snippet" ) {
            validation.add("wrongType": "The request type is not valid")
        }
        if( ! json.get("data")?.get("attributes")?.containsKey("code") ) {
            validation.add("nullCode": "No code received")
        }
        if( ! json.get("data")?.get("attributes")?.containsKey("vuln") ) {
            validation.add("nullVuln": "No vuln type specified")
        }
        if( ! json.get("data")?.get("attributes")?.containsKey("url") ) {
            validation.add("nullURL": "No callback url specified")
        }
        return validation
    }

    private validateID(String id){
        return id.matches("-?[0-9a-fA-F]+") && id.length() == 32
    }

}