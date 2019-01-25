package afip.errors

class NotValidRepository extends Error {
    NotValidRepository(String msg = "The repository is not valid, " +
            "it must start with 'https://github.com/mercadolbre/'") {
        super(msg)
    }
}