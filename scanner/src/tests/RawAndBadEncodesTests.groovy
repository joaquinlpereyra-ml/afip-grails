import afip.detectors.BadEncodingDetector
import afip.main.Conf
import afip.vulns.Vuln
import spock.lang.Specification

class RawAndBadEncodesTests extends Specification {

    def "should detect only 3 bad encodes "() {
        when:
            BadEncodingDetector badEncodingDetector = new BadEncodingDetector()
            File file =new File(Conf.fakeViewsFolder + "fakeViewWithBadEncodes.gsp")
            ArrayList<File> viewFiles = new ArrayList<>()
            viewFiles.add(file)
            badEncodingDetector.setViewFiles(viewFiles)
            ArrayList<Vuln> vulns = badEncodingDetector.findBadEncodes()

        then:
            vulns.size() == 3
    }


    def "should detect only 7 raw uses"(){
        when:
            BadEncodingDetector badEncodingDetector = new BadEncodingDetector()
            File file =new File(Conf.fakeViewsFolder + "fakeViewWithRawUses.gsp")
            ArrayList<File> viewFiles = new ArrayList<>()
            viewFiles.add(file)
            badEncodingDetector.setViewFiles(viewFiles)
            ArrayList<Vuln> vulns = badEncodingDetector.findRaw()

        then:
        vulns.size() == 7
    }


}
