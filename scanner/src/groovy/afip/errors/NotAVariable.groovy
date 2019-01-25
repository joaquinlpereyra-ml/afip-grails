package afip.errors
/**
 * Created by jlpereyra on 1/24/17.
 */
class NotAVariable extends Exception {
    NotAVariable() {
        super("This is not a variable.")
    }
}
