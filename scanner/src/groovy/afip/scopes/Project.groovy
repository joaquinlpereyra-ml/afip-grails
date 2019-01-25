package afip.scopes

import afip.files.Repository
import afip.utils.Create
import afip.vulns.Vuln
import org.codehaus.groovy.ast.ASTNode
import org.codehaus.groovy.ast.ClassNode
/** Represents a collection of Controllers and Services **/
class Project {
    List<Controller> controllers
    List<Service> services
    Config config
    DatabaseFile databaseFile

    Project() {}

    Project(Repository repository) {
        controllers = []
        services = []
        extractControllersFrom(repository)
        extractServiceFrom(repository)
        extractConfigFrom(repository)
        if (repository.getDatabaseFile()) {
            extractDatabaseFile(repository)
        }
    }

    private void extractConfigFrom(Repository repository) {
        def configAST = createASTFromFile(repository.getConfig())
        this.config = new Config(configAST.get(1) as ClassNode, repository.getConfig().getAbsolutePath())
    }

    private void extractDatabaseFile(Repository repository) {
        def dataBaseFile = createASTFromFile(repository.getDatabaseFile())
        this.databaseFile = new DatabaseFile(dataBaseFile.get(1) as ClassNode, repository.getConfig().getAbsolutePath())
    }

    private void extractControllersFrom(Repository repository) {
        def repoControllers = repository.getControllers()
        repoControllers.each { ctrl ->
            ClassNode controllerNode = createASTFromFile(ctrl).get(1) as ClassNode
            Controller controller = new Controller(controllerNode, ctrl.getAbsolutePath())
            controllers.add(controller)
        }
    }

    private void extractServiceFrom(Repository repository) {
        def repoServices= repository.getServices()
        repoServices.each { srvc ->
            ClassNode serviceNode = createASTFromFile(srvc).get(1) as ClassNode
            Service service = new Service(serviceNode, srvc.getAbsolutePath())
            services.add(service)
        }
    }

    private ArrayList<ASTNode> createASTFromFile(File file) {
        Create.AST(file.getText())
    }

    Boolean isDynamicSink(String receiver, String method, Scope currentScope, Class<? extends Vuln> vuln)  {
        ClassScope classScope = currentScope.getClassScope()
        if (receiver == null) { return false }
        if (receiver == "this") {
            if (!classScope.hasMethodOfName(method)) { return false }
            Scope methodScope = currentScope.getClassScope().findScopeOfName(method)
            if (!(methodScope instanceof Method)) { return false }
            methodScope = methodScope as Method
            return methodScope.isSinkOf(vuln)
        } else {
            String serviceName = receiver.capitalize()
            if (!hasServiceOfName(serviceName)) { return false }
            Service service = this.getServiceOfName(serviceName)
            if (!service.hasMethodOfName(method)) { return false }
            return service.getMethodOfName(method).isSinkOf(vuln)
        }
    }

    Collection<Controller> getControllers(){controllers}
    Collection<Service> getServices(){services}
    Config getConfig(){config}

    boolean hasServiceOfName(String name) {
        def res = false
        getServices().each {serve ->
            if(serve.getName() == name) res = true
        }
        res
    }

    Service getServiceOfName(String name) throws ScopeNotFoundException {
        def res
        getServices().each { serve ->
            if (serve.getName() == name ) res = serve
        }
        if (res == null) {
            throw new ScopeNotFoundException(name)
        }
        res
    }

    boolean hasControlllerOfName(String name) {
        def res = false
        getControllers().each {ctrl ->
            if(ctrl.getName() == name) res = true
        }
        res
    }

    Controller getControllerOfName(String s) {
        getControllers().find{ctrl -> ctrl.getName() == s}
    }

}
