package afip.errors;

class WrongArguments extends Exception {
    WrongArguments() {
        super("You supplied some arguments I can not understand.")
    }
}
