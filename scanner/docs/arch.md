What is the ASTs Fantastic Infosec Pilgrim?
=================================

The ASTs Fantastic Infosec Pilgrim (AFIP) is the name of a Web Security born project to use Abstract Syntax Trees (ASTs) to parse and visit source code to try and find vulnerabilities and security-related bad practices in the code using Taint Analysis mixed with some text-manipulation based techniques.

AFR Groovy is the Groovy / Grails specific implementation of the AFIP Project.

From source to vuln: a high level explanation
==================================
First, AFIP Groovy will parse the source code to create a higher level object **Project** to represent the whole project being analyzed, which is composed by a collection of objects representing the files in the repository, like **Controllers** and **Services**. Likewise, this objects contains a set of *Methods* objects to represent the methods of the file (called **MethodScopes**), which in turn contains **Variables**. The **Variables** are classified according to their type, the main types being a **Normal Variable** (for all types except maps and lists) and a **Collection Variable** (for maps and lists). The **Project** is created so the **MethodAnalyzer** can query it to gain a deeper knowledge of the methods.

After the whole **Project** is created, the **MethodAnalyzer** will start searching the **Methods** of the **Controllers** for taint in the variables. This process is managed by the **MethodTainter**. With this information **MethodAnalyzer** classifies the *Methods* as *Source* (returns a tainted **Variable**), *Cleaner* (cleans taint), *Menace* (returns a tainter **Variable** if its arguments are tainted) and *Sink* (vulnerable method if it takes a tainted **Variable** as argument). When this is done the **MethodAnalyzer** will start running the detectors in order to try to refine the taint analysis by confirming or denying the presence of a vulnerability on a tainted sink. For example, for a XSS tainted variable, it will check if the tainted value is actually used in the view.

Then the server will just return a JSON with all the vulnerabilities the detectors found on the project or snippet.

The next graph represents the **Project** structure after being created.

[AFIP Groovy Project Structure](proyect_structure.png)

This is the dependency graph for the main AFIP Components

[AFIP Groovy Dependency](dependency.png)

From source to vuln: a detailed explanation
=======================

Things to keep in mind
----------------------
1. AFIP is a **static** code analyzer. No part of the code is interpreted. Ever.
2. Even though we'll be mainly talking about ASTs in this document, AFIP has some detectors will be implemented mostly
   through regexes.
1. These are the priorities of AFIP in decreasing order.
   1. Few false positives
   2. Few false negatives
   3. Accurate information for the vulnerabilities (filepath, line number, confidence, etc)
   Keep these in mind when reading the code. If an idea would decrease the number of false negatives but increase the
   number of false positives, it is *possibly* not a good idea.


Some technical reading
----------------------
Most probably you're not familiar with ASTs nor taint analysis. This is fine. Luckily, some very smart people wrote up a
couple of papers for all of us to read and understand things even when we ourselves are pretty dumb. You probably want to
read or at least skim them:
* [OWASP on Static Code Analysis](https://www.owasp.org/index.php/Static_Code_Analysis)
* [Dynamic Taint Analysis for Automatic Detection, Analysis, and Signature Generation of Exploits on Commodity
  Software](http://bitblaze.cs.berkeley.edu/papers/taintcheck-full.pdf)
* [Pixy: A Static Analysis Tool for Detecting Web Application Vulnerabilities (Short
  Paper)](http://www.seclab.tuwien.ac.at/papers/pixy.pdf)

The AFIP architecture
----------------------
The following are the most important AFIP classes. Most of them are abstract classes except for AFIP and Scopes. If you
get the concept, understanding the concrete subclasses of them should be easy. The order is a roughly correspondent to
what happened in AFIP since Grails passes it a Github repository until the vulnerabilities are in fact discovered and
created.

<!--The *rough* order is of course a consequence of interconection between the instances of some classes. The Visitor
instances are particularly interconected with scopes and variables instances.-->

1. Scanners
2. Repository
3. GSPFile
4. MethodAnalyzer
5. Visitors
6. Variables
7. Managers
   1. BranchManager
   2. DetectorManager
8. Tainters
   1. MethodTainter
   2. ParanoidMethodTainter
9. Vulns
10. Scopes
   1. ClassScope
   2. MethodScope
11. Project

### Scanners

This is both the entry and exit point of the application. The Github URL and the desired tags are received and will
create a **Repository** (not to be confused with **Project**) downloading the repository in the process.
Having the **Repository** it'll create the **Project**, the **DetectorManager** and the **MethodAnalyzer**. With this it'll start the analysis of the project,
which consists of various bad practices (code-named 'LilCodes' in the code), security misconfigurations, badly encoded *.gsp* files and actual
vulnerabilities like XSS in the controllers. The order of the operations is important, as a correctly configured Grails project can
in fact prevent most XSS, so this is taken into account.

The instances of the scanners are **RepositoryScanner** (scans an entire Grails Repository) and the **SnippetScanner** (scans a string).

### Repository

The **Repository** is the class responsible for the Github repository management. This includes downloading the repository, managing the files on disk, changing between tags and being able to answers specific questions about the repository.

The repository uses an internal private class to communicate with Github called **GitClient**.

The **Repository** will take the folder downloaded by the **GitClient** and will try to extract:
* The grails folder from inside the repository
* The config folder of the grails folder
* The controllers folder of the grails folder
* The views folder of that grails folder
* The services folder of that grails folder

AFIP can function without a views and a services folder, but *must* find a config and a controllers folder.
It is also a precondition that there's only *one* valid (where valid means with a config and controllers folder) Grails
folder inside the whole repository. If any of these precondition are not met, AFIP will raise a *NotAGrailsRepository* error.

We know exactly where certain important files are located, like the *Config.groovy* file and all the controllers and
views. This will be used by the **MethodAnalyzer** and the visitors.  
###  GSPFile

The **GSPFile** is mainly used in the manipulation of *.gsp* view files later on the process to actually
detect some vulnerabilities where the views are involved.

### MethodAnalyzer

The analyzer is AFIP's centre of operations.

It can analyze a **MethodScope** to classify it (either as a *Cleaner*, a *Sink*, a *Menace* or a *Source*). It works together with the **MethodTainter** for this. The _how_ will be detailed further ahead in the **MethodTainter** section but basically the **MethodTainter** can trigger new analysis of methods called inside the current method being analyzed. If it does trigger a new analysis, the analyzer will pause the current method analysis and stack it, then it will proceed with a new analysis for this new method encountered.
This process goes on and on stacking methods till it finishes analyzing a method when the method does not call any other method. Then the analyzer will pop the previous method from the stack and it will continue the paused analysis. In the process of analyzing methods it could encounter a call for a method currently in the stack. In that case it will throw an **CircularAnalysisException** and mark the method as analyzed.

The next figure show the process of classifying an imaginary "fooMethod" which in turn calls another method named "barMethod" that does not make method calls

[AFIP Groovy High Level Analysis Process](analyzer.png)

After all the important methods (usually the methods in the controllers), it starts looking for vulns with the **DetectorManager**. The whole process is managed the **DetectorManager**.

#### Classification
Further detail of the classified methods can be found on the **MethodScope** section, in this section we'll discuss the logic to classify them.
##### Cleaner
To find if a **MethodScope** is a *Cleaner* we assume the parameters of the method to be tainted. After the tainter finishes, if the returned variables are not tainted, it means the method *cleaned* the variable
##### Menace
To find if a **MethodScope** is a *Menace* we first assume the parameters to be tainted; if the returned variable is tainted, then we reset the variables and check what happens when the parameters are not tainted; if the result is not tainted, then it means the method is a *menace*.
##### Sink
To find if a **MethodScope** is a *Sink* we assume the parameters to be tainted; we spread the taint, and then call the **DetectorManager** to try to find vulnerabilities. If found, the method per se is a vulnerability (or *Sink*).
##### Source
To find if a **MethodScope** is a *Source* we assume the parameters to be clean. After the tainter finishes, if the returned variables are tainted, then the method is a source of taint.

It is also important to note that after each analysis, it tells the variables to reset themselves, so further analysis will not be influenced by previous taint results.

### Visitors

The Visitors are classes which main purpose is to traverse the AST and either modify it or extract useful information
from it. This processes are done while the **Project** is being created.
In order of execution, they are:

1. The **ClassVisitor**: extracts from a class AST all its methods and fields. The fields are converted inmediatly to
   variables, all the methods are saved for later, and there's a special field to save all the method's which start with
   'get' for the getter visitor to inspect. (In case you're wondering, yes, the second list is a subset of the first
   one.)
2. The **MethodCanonizator**: modify each of the methods extracted in the previous step so that every one of them looks
   like a normalized version of it which is easier to analyze, e.g, make explicit all the implicit *return statements*.
3. The **GetterVisitor**: visit all the methods in the specially saved field by the class visitor which held only 'getter'
   methods. Inspect their return type to the best of our knowledge and create variables with the appropiate type.
4. The **VariableCreator**: inspect the whole AST and create all the variables to make a more in depth analysis possible.
   The Variable class and it's interface is possibly the BranchManager most useful aspect of AFIP if you're trying to add a new
   feature (like a new vulnerability to detect) and it will be explained in more depth in the next section.

### The Variables
The **Variables** represent actual variables in the program and provide an interface to ask things about them. There's 1
abstract super class, 5 concrete subclasses and 2 interfaces associated with them.

The abstract class is the **Variable** class. It holds common functionality across all variables, but most importantly, it
implements the *variable creators*. This *must* be used when creating variables instead of the initializers of each
subclass. Luckily, all the *variable creators* share the same signature:

```groovy
static Variable createVariable(ASTNode node, Scope scope, Integer branches)
```

The ASTNode parameter may be a *MethodCallExpresssion*, a *VariableExpression*, a *Paramater*, *BinaryExpression* or a *ReturnStatement*.

The returning type Variable may be an instance of four concrete subclasses of Variable (it will never be a
*CollectionEntry*).

The two interfaces associated with a Variable are:
* **Dangerous**: a variable which may represent a danger if it gets to a sink.
* **Taintable**: a variable which may be directly tainted by the user.

It is important to note all taintable variables are also dangerous.

The five concrete subclasses of the **Variable** abstract class are:
##### NormalVariable (implements Taintable)
Represent a normal Groovy variable, eg:

```groovy
def a = 'hola'
```

#### CollectionVariable (implements Dangerous)
Represents a collection of variables, like a list or a map. AFIP treats lists
as maps which keys are their index, so

```groovy
def abc = ['a', 'b', 'c']
```

would, for AFIP, be the same as
```
def abc = [0: 'a', 1: 'b', 2: 'c']
```

Importantly, AFIP also considers method calls to be maps. So
```groovy
instance.method(arg1, arg2)
```

is interpreted as:
```groovy
def method = ["receiver0": instance, "0": arg1, "1": arg2]
```

A **CollectionVariable** is not **Taintable** because you can never actually taint a whole list, rather, you taint an element of
a list. If an element of a list is tainted, the list is considered dangerous.

#### CollectionEntry (implements Taintable)
Represent an entry inside a **CollectionVariable**. Continuing with our examples before, the code

```groovy
def abc = ['a', 'b', 'c']
```
would have the **CollectionVariable** 'abc', which would contain three **CollectionEntry** instances of name 0, 1 and 2.

This is why the createVariable method will never return a CollectionEntry: they are accessible only through the
collection variable associated with them, with the *getEntry(String key)*

#### ParameterVariable (implements Dangerous)
A **ParameterVariable** represent parameters inside a function. It is special because we've got almost no information about
them. The **MethodTainter** considers them safe and the **ParanoidMethodTainter** considers them unsafe

#### ReturnVariable (implements Dangerous)
A **ReturnVariable** represent the return inside a function. It is special because we've got almost no information about
them, and we consider them dangerous against all vulnerabilities by default.


#### UnknownVariable (extends NormalVariable)
A special type of **NormalVariable** which value is unknown. Used, for example, in field declarations.

### The Managers

There are two managers, the **DetectorManager** and the **BranchManager**.

The managers work a little like visitors, but instead of an AST they receive Variable instances.

####The Branch Manager

The **BranchManager** aids variable creation by informing the program of how many possible branches of execution there are in
the program at certain point, which translates to how many possible meaning of a variable there are.

#### The Detector Manager

The **DetectorManager** actually is a centralizer of all the detectors registered in the beginning of the program. There is
a one to many relationship between detector and vulnerability.

The **DetectorManager** receives a **Variable** instance through its *detect* method and then passes it through all the
registered detectors.

Each of *detectors* must be implement as well a *detect* method which receives any type of **Variable**. It will perform
all the final checks on a variable to decide if there's a vulnerability present in it. The specific process
will vary from vulnerability to vulnerability. For example, the Reflected XSS detector will:

1. Check that the received variable is a 'render' method call.
2. Check that the 'model' entry of the variable is actually tainted.
3. Check that the tainted entries of the 'model' map are actually used in the view found in the 'view' entry of the render.
4. Check that there are no safe content types designated in the render.
5. Check that the view entry of the render is not a static view.

If all of this holds, it will create and return a XSS vulnerability.

As said, the specific process of a detector will vary from vulnerability to vulnerability.

### The Tainters

The *tainters* receives **MethodScopes** and recursively inspect their nodes to know if they are tainted for a set of vulnerabilities.
Right know, the only thing that can make a previously untainted variable be tainted is to come from variables called *'params'* or *'request'*
or be defined in terms of a variable which is already tainted. They also can be tainted if they pass through a *Source*. If a **Variable** passes through a *Menace*, it can be tainted if the parameters of the *Menace* are tainted too.

The *tainters* can also *clean* (or *untaint*) a variables if it passes through a *Cleaner* method or if it has no more possible definitions which are tainted (for example, by shadowing the variable with a new value).

It is important to note that in AFIP, taint is not an absolute term: a variable can be tainted for XSS but untainted for
SQL Injection. This gives us the possibility to define different safety functions for different vulnerabilities. This also happens for classified **MethodScopes**. They can be a *Cleaner* for certain vulnerability and at the same time be a *Source* for another.

There are two implementations of the tainter:

#### MethodTainter
The **MethodTainter** assumes that the parameters of a function are not tainted.

#### ParanoidMethodTainter
The **ParanoidMethodTainter** assumes that the parameters of a function are tainted.

### Vulnerabilities

Vulnerabilities represent just that, vulnerabilities. They are created by the detectors, which give them back to the
AFIP main instance, which in turn gives them to the AFIP server to display as JSON.

There's not much magic here. The only important thing to know: if you create a detector, you *must* create at least a
vulnerability for it.

### Scopes
Scopes represents the visibility of a **Variable**. In other words, which parts of the **Project** access it. A **Scope** can have an *outerScope* (or parent) and *innerScopes* (or children); that is, the scopes have a *tree* structure. Every **Scope** contains a set of variables which can access. This variables can be defined in the said **Scope** or in the *outerScope* (if it has one), but cannot access it's *innerScopes* variables.

It can be queried about its variables with *hasVariableOfName* and *getVariableOfName*.
It can be queried about its *innerScopes* with *findScopeOfName*.

There are three subclasses of **Scope**:

#### ClassScope

The **ClassScope** represents a class file in the project. It has the *filePath* of the file in the repository.
It uses the visitors for two things: extract the methods of the file and save them as *Methods*, and to extract the class variables (*getterVariables*).

You can query for a specific method using its name with *hasMethodOfName* and *getMethodOfName*

There are four subclasses of **ClassScope**, each represent different types of files in the repository: **Controllers**, **Services**, **DatabaseFile** and **Conf**.

#### MethodScope

The **MethodScope** represents a method in a file. It uses the visitors to extract the variables.
It can be classified by the **MethodAnalyzer** into four types: *Source*, *Cleaner*, *Sink* and *Menace*.

You can test if it is a *Source*, *Cleaner*, *Sink* or *Menace* for a vulnerability with *isSourceOf*, *isCleanerOf*, *isSinkOf* and *isMenaceOf*. Also, you can retrieve the vulnerabilities for which the method is a *sourceOf*, *cleanerOf*, *sinkOf* or *menaceOf* with their respective *getters*

#### Project
The **Project** is the biggest scope. It contains all the **Services** and **Controllers**, the **Conf** and **DatabaseFile**. It can tested for the services and controllers with *hasServiceOfName* and *hasControllerOfName*. To get a specific service or controller use *getServiceOfName* and *getControllerOfName*.
When creating the **Project**, it would use the **Repository** to get to the files and call their respective constructors (**Controllers**, etc).
