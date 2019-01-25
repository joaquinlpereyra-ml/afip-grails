package afip.files

import org.apache.commons.logging.LogFactory

class GSPFile {
    private File gsp
    private static final log = LogFactory.getLog(this)

    GSPFile(String path) {
        gsp = new File(path)
    }

    GSPFile(File gsp) {
        this.gsp = gsp
    }

    /**
     * @param file the file to be searched
     * @param variables the afip.variables names to be searched on the file
     * @return true if any of the afip.variables was found on the file, false otherwise
     */
    boolean findUsage(ArrayList<String> variables) {
        String fileBody = extractBody()
        for (String variable : variables) {
            if (fileBody.contains(variable)) {
                return true
            }
        }
        return false
    }

    /**
     * Extracts the text between the body tags of the html.
     * @param htmlText: the complete HTML.
     * @return: a string with only the text between body tags.
     */
    private String extractBody() {
        String htmlText = gsp.getText()
        if (!htmlText.contains('<body>')) {
            return htmlText
        }
        String bodyOnlyHtmlText = htmlText.split("(ml:)?body")[1].split("/(ml:)?body")[0]
        if (bodyOnlyHtmlText.contains('body>')) {
            log.error(["title": "html contains body still", "html": bodyOnlyHtmlText])
        }
        return bodyOnlyHtmlText
    }
}
