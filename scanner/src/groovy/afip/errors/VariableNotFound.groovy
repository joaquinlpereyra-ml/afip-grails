package afip.errors

class VariableNotFound extends Exception {

    VariableNotFound(String variableName) {
        super("You tried to get the variable of name: " + variableName + ". This variable is not registered")
    }

}