class UrlMappings {

	static mappings = {
		"/ping" (controller: 'Ping', action: 'index')
		"/playground" ( controller : 'Playground', action : [GET: "unsupported", POST: "snippetAnalyser"] )
	}
}
