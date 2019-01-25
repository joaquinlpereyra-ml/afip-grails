class ValidController {

    def validService

    void notMethod(){
        def b = params.danger
        b = validService.cleaner(b)
        def c = new File(b)
        c.Write()
    }

    def vulnerable(){
        def a = validService.source()
        render(model: a)
    }

    def callingMD5() {
        def md5 = validService.getMD5()
        render(md5)
    }
}
