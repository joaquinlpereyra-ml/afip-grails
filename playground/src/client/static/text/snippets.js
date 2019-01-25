const openredirect = 
`def isValidURL(text) {
  return text.startsWith("https://mercadolibre.com")
}

def someController() {
  def url = params.url
  if (!(isValidURL(url))) {
    url = "https://mercadolibre.com"
  }
  redirect(url: url)
}`;

const remotecodeexecution = 
`def rceController() {
	def command =  params.command
	if (something) {
	    command = 'ls'
	}
	command.execute()	
}`;

const pathtraversal =
`def filePath = params.file
def file = new File(filePath)
def f2 = file.Read()
`;

const xmlexternalentitiesattack =
`def vulnerableXSSParser = new XmlSlurper();
if (something) {
    vulnerableXSSParser.setFeature("http://xml.org/sax/features/external-general-entities", false)
}
vulnerableXSSParser.parseText(something)
`;

const massassignment =
`sillyConstructor = Class(params)
`;

const snippets = {
	'Open Redirect': openredirect,
	'Remote code execution': remotecodeexecution,
  'Path traversal': pathtraversal,
  'XML external entities attack': xmlexternalentitiesattack,
  'Mass Assignment': massassignment 
}

export default snippets;