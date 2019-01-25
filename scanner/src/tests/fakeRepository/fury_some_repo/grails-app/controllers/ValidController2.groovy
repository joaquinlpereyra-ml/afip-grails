class ValidController2 {

    def validService

    void notMethod(){
        def b = params.danger
        b = foo(b)
        def c = new File(b)
        c.Write()
    }
}
