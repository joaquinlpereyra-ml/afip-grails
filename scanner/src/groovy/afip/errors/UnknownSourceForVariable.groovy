package afip.errors
/**
 * Created by jlpereyra on 1/24/17.
 */
class UnknownSourceForVariable extends Exception {
    UnknownSourceForVariable() {
        super("You tried to add a variable of unknown source. This is a bug and you shouldn't catch this")
    }
}
