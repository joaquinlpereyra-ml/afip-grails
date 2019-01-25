package afip.files

import afip.errors.CantFindRef
import afip.errors.NotFoundRepository
import afip.main.Conf
import groovy.io.FileType
import groovy.io.FileVisitResult
import org.apache.commons.io.FileUtils
import org.apache.commons.logging.LogFactory
import org.eclipse.jgit.api.Git
import org.eclipse.jgit.api.errors.InvalidRemoteException
import org.eclipse.jgit.api.errors.RefNotAdvertisedException
import org.eclipse.jgit.internal.storage.file.FileRepository
import org.eclipse.jgit.transport.UsernamePasswordCredentialsProvider

class Repository {

    /**
     * GitClient handles most of the git-specific logic. It will clone or fetch
     * the repository according to the scope we are in
     */
    private class GitClient {
        private Git git

        GitClient(String URL, File destination) throws NotFoundRepository {
            UsernamePasswordCredentialsProvider creds = new UsernamePasswordCredentialsProvider(
                    System.env.GITHUB_USER,
                    System.env.GITHUB_TOKEN
            )
            if (!destination.exists() || Conf.scope) {
                try{
                    git  = Git.cloneRepository()
                            .setURI(URL)
                            .setCredentialsProvider(creds)
                            .setDirectory(destination)
                            .call()
                } catch (InvalidRemoteException t) {
                    throw new NotFoundRepository()
                }

            }  else {
                git = new Git(new FileRepository(destination.getPath() + '/.git'))
                git.fetch().setCredentialsProvider(creds).call()
            }
        }

        void setTag(String tag) throws RefNotAdvertisedException {
            git.checkout().setName("refs/tags/"+tag).call()
        }

    }

    private String name
    private String id
    private File folder
    private ArrayList<String> tags
    private GitClient git

    private Boolean isGrails

    public File grailsAppFolder
    public File confFolder
    public File controllersFolder
    public File viewsFolder
    public File servicesFolder

    private static final log = LogFactory.getLog(this)

    /**
     * A constructor to initialze a repository without git support.
     * This may be a deformed repository without a .git folder
     * It will not support operations which depend on git, like changing tags.
     * @param repositoryFolder
     * @param id
     */
    Repository(File repositoryFolder, String id) {
        this.id = id
        this.name = repositoryFolder.getName()
        this.folder = repositoryFolder
        this.tags = []
        ArrayList<File> allGrailsAppFolder = findAllGrailsAppFolder()
        File realGrailsFolder = findRealGrailsAppFolder(allGrailsAppFolder)
        if (realGrailsFolder) {
            isGrails = true
            grailsAppFolder = realGrailsFolder
            findConfigsFolder(grailsAppFolder)
            findControllerFolder(grailsAppFolder)
            findViewsFolder(grailsAppFolder)
            findServicesFolder(grailsAppFolder)
        } else {
            isGrails = false
        }

    }

    /**
     * A normal repository. A git client will clone the repository
     * from the specified URL or fetch if the folder already exists.
     */
    Repository(String URL, List<String> tags, String id) throws NotFoundRepository {
        this.tags = tags
        this.id = id
        this.name = setName(URL)
        this.folder = getFolder()
        this.git = new GitClient(URL, folder)
        ArrayList<File> allGrailsAppFolder = findAllGrailsAppFolder()
        File realGrailsFolder = findRealGrailsAppFolder(allGrailsAppFolder)
        if (realGrailsFolder) {
            isGrails = true
            grailsAppFolder = realGrailsFolder
            findConfigsFolder(grailsAppFolder)
            findControllerFolder(grailsAppFolder)
            findViewsFolder(grailsAppFolder)
            findServicesFolder(grailsAppFolder)
        } else {
            isGrails = false
        }
    }

    private File getFolder() {
        File repositoriesFilder = new File('repositories/')
        if (Conf.scope && repositoriesFilder.exists()) {
            FileUtils.cleanDirectory(repositoriesFilder)
        }
        File repositoryFolder = new File(repositoriesFilder.getCanonicalPath() + '/' + name)
        return repositoryFolder
    }

    private setName(String URL) {
        return URL.tokenize('/').get(3)
    }

    String getName() {
        return name
    }

    /** Return a list of all the tags with which this repository was created */
    ArrayList<String> getTags() {
        return tags
    }

    /**
     * Will change the tag to the specified string.
     * @param tag
     * @throws CantFindRef, if it can't find the tag you're referring to.
     */
    void changeTag(String tag) throws CantFindRef {
        try {
            git.setTag(tag)
        } catch (RefNotAdvertisedException _) {
            throw new CantFindRef(name, tag, id)
        }
    }

    /** Is the repository a valid Grails repository? */
    Boolean isGrails() {
        return isGrails
    }

    /** Do a preliminary search for the grails app folders. It will match all folders named grails-app. */
    private ArrayList<File> findAllGrailsAppFolder() {
        ArrayList<File> allGrailsAppFolder = new ArrayList<>()
        folder.traverse(type: FileType.DIRECTORIES, { if (it.getName() == 'grails-app') {allGrailsAppFolder.add(it)}} )
        //log.debug(['title': 'found grails-app folders', 'folders': allGrailsAppFolder])
        return allGrailsAppFolder
    }

    /**
     * Will filter from a list of possible grails app folders. Will return the most possible value
     * for the real grails app folder (no compile code and several config and controller folders present).
     * @param allGrailsAppFolder
     * @return: the most possible grails app folder or null, if none found
     */
    private File findRealGrailsAppFolder(ArrayList<File> allGrailsAppFolder) {
        ArrayList<File> validGrailsAppFolder = new ArrayList<>()
        for (File grailsAppFolder : allGrailsAppFolder) {
            Boolean hasConf = false
            Boolean hasController = false
            Boolean isPlugin = false
            // workaround for people pushing their compiled project on to github
            if (grailsAppFolder.getPath().contains('/target/')) { continue }
            grailsAppFolder.traverse (type: FileType.DIRECTORIES, maxDepth: 0, {if (it.getName() == 'conf') {hasConf = true}} )
            grailsAppFolder.traverse (type: FileType.DIRECTORIES, maxDepth: 0, {if (it.getName() == 'controllers') {hasController = true}} )
            if (hasConf && hasController && (! isPlugin)) { validGrailsAppFolder.add(grailsAppFolder) }
        }
        if (validGrailsAppFolder.size() != 1) {
            //log.debug(['title': 'valid grails app folder size is not one', 'size': validGrailsAppFolder.size(), 'folders': validGrailsAppFolder.collect { it.getPath() } ] )
            return null
        }
        //log.debug(['title': 'unique valid grails app folder found', 'path': validGrailsAppFolder.get(0).getPath()])
        return validGrailsAppFolder.first()
    }

    private boolean isTestOrMock(File file) {
        return file.getName().toLowerCase().contains("mock") || file.getName().toLowerCase().contains('test')
    }


    /**
     * Closure to search for a directory of name nameToSearch and
     * save it on the public field of name giveMeValueToSaveOn
     */
    private pathSaver(String nameToSearch, String giveMeValueToSaveOn) {
        // this must be outside the inner closure
        // because of groovy magic and how it separates this in classes
        // when compiling :)
        def _class = this.getClass()
        def _field = _class.getDeclaredField(giveMeValueToSaveOn)
        def lookIt = {
            if (it.name == nameToSearch) {
                _field.set(this, it);
                FileVisitResult.TERMINATE
            }
        }
        return lookIt
    }


    /**
     * Save the directory named conf found inside the grailsAppfolder on the confFolder field
     */
    private void findConfigsFolder(File grailsAppFolder) {
        grailsAppFolder.traverse(type: FileType.DIRECTORIES, pathSaver('conf', 'confFolder'))
    }

    /**
     * Save the directory named controllers inside the grailsAppFolder File on the controllersFolder field
     */
    private void findControllerFolder(File grailsAppFolder) {
        grailsAppFolder.traverse(type: FileType.DIRECTORIES, maxDepth: 0, pathSaver('controllers', 'controllersFolder'))
    }

    /**
     * Save the directory named views inside grailsAppFolder on the controllersFolder field
     */
    private void findViewsFolder(File grailsAppFolder) {
        grailsAppFolder.traverse(type: FileType.DIRECTORIES, maxDepth: 0, pathSaver('views', 'viewsFolder'))
        if (viewsFolder == null) { viewsFolder = new File('mockedViews')}
    }

    /**
     * Save the services folder on the servicesFolder field
     */
    private void findServicesFolder(File grailsAppFolder) {
        grailsAppFolder.traverse(type: FileType.DIRECTORIES, maxDepth: 0, pathSaver('services','servicesFolder'))

        // the servicesFolder may as well not be present in a directory.
        // create an empty mock representation of one if thats the case to avoid null pointer exceptions
        if(servicesFolder == null) { servicesFolder = new File("mockedServices")}
    }

    /**
     * Returns all the configuration files of the project.
     */
    ArrayList<File> getConfigs() {
        ArrayList<File> configFiles = new ArrayList<File>()
        confFolder.traverse { if (!it.isDirectory()) { configFiles.add(it) } }
        return configFiles
    }

    /**
     * Returns all the controllers of the project.
     */
    ArrayList<File> getControllers() {
        ArrayList<File> controllerFiles = new ArrayList<File>()
        controllersFolder.traverse {
            if (!it.isDirectory() && it.getName().endsWith('.groovy') && !isTestOrMock(it) ) {
                controllerFiles.add(it)
            } }
        return controllerFiles
    }

    /** Return the views folder */
    File getViewsFolder() {
        return viewsFolder
    }

    /**
     * Returns all the views of the project.
     */
    ArrayList<File> getViews(){
        ArrayList<File> viewFiles = new ArrayList<>()
        if( viewsFolder.getAbsolutePath().endsWith("mockedViews") ) { return [] }
        viewsFolder.traverse{ if (!(it.isDirectory() || it.getName().startsWith('.') || it.length() == 0)) {viewFiles.add(it)}}
        return viewFiles
    }

    /**
     * Returns a list of services found on the project
     */
    ArrayList<File> getServices() {
        ArrayList<File> servicesFiles = new ArrayList<File>()
        if( servicesFolder.getAbsolutePath().endsWith("mockedServices") ) { return [] }
        servicesFolder.traverse {
            if (!(it.isDirectory() || it.getName().startsWith('.') || it.getName().startsWith('_') || it.length() == 0 || isTestOrMock(it))) {
                servicesFiles.add(it)
            }
        }
        return servicesFiles
    }

    /**
     * Return the main configuration file ('afip.main.Conf.groovy') of the project.
     * @return: a file or null, if not found
     */
    File getConfig() {
        File mainConfigFile
        confFolder.traverse(type: FileType.FILES, { if (it.getName() == 'Config.groovy') {mainConfigFile = it}})
        assert mainConfigFile
        return mainConfigFile
    }

    /**
     * Returns the UrlMappings.groovy file of the project.
     * @return a file or null, if not found.
     */
    File getUrlMappings() {
        File urlMappingFile
        confFolder.traverse(type: FileType.FILES, { if (it.getName().endsWith('UrlMappings.groovy')) urlMappingFile = it})
        return urlMappingFile
    }

    /**
     * Return the main database file of the project.
     * @return: a file or null, if not found
     */
    File getDatabaseFile() {
        File databaseFile
        confFolder.traverse(type: FileType.FILES, {if (it.getName().endsWith('DataSource.groovy')) databaseFile = it})
        return databaseFile
    }

    /**
     * Will explore the 'where' file looking for either a file or a directory
     * which matches EXACTLY the name given as a second parameter
     * @return: a file or null, if not found
     */
    static File findFileOrDir(File where, String name) {
        File result
        where.traverse({
            if (it.getName() == name) {
                result = it
                FileVisitResult.TERMINATE
            }
        } )
        return result
    }

    /**
     * Searches the 'where' Folder and returns all the files (NOT folders) which matches
     * the 'search' string either directly by name or by full path.
     * IE: you can pass it 'readme.txt' and 'where/readme.txt' as search strings and readme.txt
     * will be found inside of 'where' for any of them
     * @param where: where to search for the files
     * @param search:  a filename or path to be matched
     * @return: an array list of all the files which matched the search
     */
    static ArrayList<File> findFile(File where, String search) {
        ArrayList<File> files = new ArrayList<File>()

        where.traverse( {
            if (it.getName() == search && it.isFile()) {
                files.add(it)
            }
        })
        return files
    }

    /**
     * Search the 'where' Folder and returns the files which start with the 'what'
     * @param where: where to search
     * @param what: what to search
     * @return: a list of files in the where that started with the what
     */
    static ArrayList<File> findFileBegginingWith(File where, String what) {
        ArrayList<File> files = new ArrayList<File>()
        where.traverse( {
            if (it.getName().startsWith(what) && it.isFile()) {
                files.add(it)
            }
        })
        return files
    }

    /**
     * Search the 'where' folder for files containing the 'what'.
     * @param where: where to search
     * @param what: what to search
     * @return: a list of files in the where that contained the what
     */
    static ArrayList<File> findFilesContaining(File where, String what) {
        ArrayList<File> files = new ArrayList<File>()
        where.traverse( {
            if (it.getName().contains(what) && it.isFile()) {
                files.add(it)
            }
        })
        return files
    }

    /**
     * Splits the 'what' with a list of common delimiters ('-', '_', '.').
     * Then find files which are equal to any of the splitted terms.
     * For example, if the 'what' is 'my-file_is', it will look for files named
     * 'my', 'file', 'my-file', 'file_is', and 'is'.
     * @param where: where to search
     * @param what: what to search
     * @return: a list of files in the where that contained the what
     */
    static ArrayList<File> findSplittedTerms(File where, String what) {
        ArrayList<File> foundFiles = new ArrayList<File>()
        ArrayList<String> commonSeparators = ['-', '_', '.']
        ArrayList<String> splittedWhat = new ArrayList<String>()
        for (String separator : commonSeparators) {
            for (String splitted : what.tokenize(separator)) {
                if (! splitted.endsWith('.gsp')) {
                    splitted = splitted + '.gsp'
                }
                splittedWhat.add(splitted);
            }
        }
        for (String splitted : splittedWhat) {
            where.traverse( {
                if (it.getName() == splitted && it.isFile()) {
                    foundFiles.add(it)
                }
            })
        }
        return foundFiles
    }

    /**
     * Given a possibleViewPath, tries to extract the path from this string and
     * returns a list of files which match the real view path.
     *
     * If the possibleViewPath contains a string inside parameters, it will consider
     * that string to be the real view path. Else, it will consider the original view path
     * to be the real view path. You should pass the path without the '.gsp' ending.
     * Examples og how this function interprets the 'possibleViewPath
     *     thisIsAFunction('andThisIsAFile') -> 'andThisIsAFile.gsp'
     *     'thisIsAFile' -> 'thisIsAFile.gsp'
     *
     * @param viewsFolder: the views folder for the grails project.
     * @param possibleViewPath: the possible view path.
     * @return: an array list of Files which matched the real view path
     */
    static ArrayList<File> findAllViews(File viewsFolder, String possibleViewPath) {
        String insideParenthesis = ""
        if (possibleViewPath.contains("(") && possibleViewPath.contains(")")) {
            insideParenthesis = possibleViewPath.substring(possibleViewPath.indexOf("(") + 1, possibleViewPath.indexOf(")"))
        }
        String stringToSearch = insideParenthesis ?: possibleViewPath
        stringToSearch = stringToSearch.tokenize('/')[-1]

        // we'll try to provide the list with the most precise match
        ArrayList<File> hopefullyAnExactMatch = findFile(viewsFolder, stringToSearch + '.gsp')
        if (hopefullyAnExactMatch) {return hopefullyAnExactMatch}
        ArrayList<File> hopefullyFilesBegginingWithTheSearch = findFileBegginingWith(viewsFolder, stringToSearch)
        if (hopefullyFilesBegginingWithTheSearch) {return hopefullyFilesBegginingWithTheSearch}
        ArrayList<File> hopefullyFilesMatchingSplittedName = findSplittedTerms(viewsFolder, stringToSearch)
        if (hopefullyFilesMatchingSplittedName) { return hopefullyFilesMatchingSplittedName }
        ArrayList<File> hopefullySomethingAtLeastContainingOurSearch = findFilesContaining(viewsFolder, stringToSearch)
        return hopefullySomethingAtLeastContainingOurSearch // well... there's nothing better we can do
    }


}
