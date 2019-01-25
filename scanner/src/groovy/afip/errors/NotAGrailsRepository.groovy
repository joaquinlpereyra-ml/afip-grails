package afip.errors

class NotAGrailsRepository extends NotValidRepository {
    NotAGrailsRepository() {
        super("This does not seem to be a Grails repository")
    }
}
