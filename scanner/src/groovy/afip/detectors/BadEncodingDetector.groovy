package afip.detectors

import afip.variables.Variable
import afip.vulns.BadEncodingVuln
import afip.vulns.Vuln
import org.apache.commons.logging.LogFactory
/**
 * Detects usages of bad encodings on .gsp files.
 */
class BadEncodingDetector extends Detector{
    private static final log = LogFactory.getLog(this)
    public ArrayList<File> viewFiles
    BadEncodingDetector(){
        super(BadEncodingVuln, [], [])
    }

    void setViewFiles(ArrayList<File> viewFiles){
        this.viewFiles = viewFiles
    }
    /** findRaw methods detects raw uses in .gsp files without the correct encode.
     */
    ArrayList<Vuln> findRaw(){
        log.debug(["title": "starting detection", "vuln": "bad encoding","type":"raw encodes"])
        ArrayList<Vuln> vulns = new ArrayList<>()
        for(File viewFile : viewFiles){
            ArrayList<String> lines = viewFile.readLines()
            String raw = '\\$raw\\{\\(.*\\)\\}'
            String raw2 = '\\$\\{.*\\.encodeAsRaw\\(\\)\\}'
            String raw3 = '<g:encodeAs codec=("(Raw|raw)?"|"(None|none)?")>\\$\\{.*\\}<\\/g:encodeAs>'
            int lineNumber = 1
            for(String line : lines) {
                if ((line =~ raw) || (line =~ raw2) || (line =~ raw3)) {
                    vulns.add(new BadEncodingVuln(viewFile.getPath(), lineNumber, line))
                }
                lineNumber++
            }
        }
        return vulns
    }

    /**
     * findBadEncodes detects bad uses of the internationalization prints without the properly encode
     */

    ArrayList<Vuln> findBadEncodes(){
        log.debug(["title": "starting detection", "vuln": "bad encoding","type":"bad encodes"])
        ArrayList<Vuln> vulns = new ArrayList<>()
        for(File viewFile : viewFiles){
            String raw = '<%=((?!t9n).)*%>'
            String raw2 = '<%=t9n.tr\\(.*encoding:"(none|None|NONE)"'
            String raw3 = '.*encodeAsHTML.*'
            String raw4 = 'f:\\[.*\\].*'
            ArrayList<String> lines = viewFile.readLines()
            int lineNumber = 1
            for (String line : lines) {
                if((line =~ raw) || line =~raw2 && !(line =~raw3) && line =~raw4) {
                    vulns.add(new BadEncodingVuln(viewFile.getPath(),lineNumber,line))
                }
                else if(line =~raw2 && line =~raw3){
                    vulns.add(new BadEncodingVuln(viewFile.getPath(), lineNumber, line))
                }
                lineNumber += 1
            }
        }

        return vulns
    }

    ArrayList<Vuln> detect(Variable var) {
        return []
    }
}
