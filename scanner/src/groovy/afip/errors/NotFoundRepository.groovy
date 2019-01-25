
package afip.errors

class NotFoundRepository extends NotValidRepository {
    NotFoundRepository() {
        super("This repository could not be found ")
    }
}