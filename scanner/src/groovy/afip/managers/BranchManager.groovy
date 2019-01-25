package afip.managers

import org.codehaus.groovy.ast.stmt.SwitchStatement

/**
 * This class defines the necessary logic to handle branching (if-else statements, try/except statments and switch statments).
 * When visiting a new branching node, you should call the corresponding method here, to keep track of how many
 * branches are in the current point of execution for the program.
 * You should also call the necessary methods when leaving the branching node.
 */
class BranchManager {
    Integer totalBranches = 1  // before entering any statement, there are only zero branches

    /** Return the amount of branches presently in the program */
    Integer getAmountBranches() {return totalBranches}

    /** Inform the branch manager that we're entering a new branch (if/else or try/except) */
    void enterNewBranching() { totalBranches++ }

    /** Inform the branch manager that we're entering a new switch statatement, which could branch our program several times */
    void enterNewBranching(SwitchStatement switchStatement) {
        /* NOTE: surprisingly, nothings needs to be done with the default statement.
           this is because we can think about the default statement in a switch as a continuation of your main branch
           instead of a splitting of it. it is the same reasoning we use to add only one branch for every if / else
           instead of adding one for the if and another for the else
         */

        totalBranches += switchStatement.getCaseStatements().size()
    }

    /** Inform the branch manager we're leaving a branch (if/else or try/except) */
    void leaveBranching() { totalBranches-- }

    /** Inform the branch manager we're leaving a switch statement, which could have branched our program several times */
    void leaveBranching(SwitchStatement switchStatement) {
        /* NOTE: please see note on enterNewBranching(SwitchStatement switch) for info on how to deal with default statements */
        totalBranches -= switchStatement.getCaseStatements().size()
    }
}
