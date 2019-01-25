package afip.errors

class CircularAnalysisException extends Exception{
    CircularAnalysisException(){
        super("Circular analysis found")
    }
}
