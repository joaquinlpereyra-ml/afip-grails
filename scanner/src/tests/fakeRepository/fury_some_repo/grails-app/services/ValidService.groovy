class ValidService{
    String cleaner(String a) {
        a = a.getCanonicalPath()
    }

    def source(){
        return params.a
    }

    def getMD5() {
        return "hola".encodeAsMD5()
    }
}