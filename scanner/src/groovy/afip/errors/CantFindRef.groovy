package afip.errors

class CantFindRef extends Exception {
    CantFindRef(String repo, String branch, String scanHash) {
        super("Can't find branch " + branch + " on repository " + repo + " on scan " + scanHash)
    }
}
