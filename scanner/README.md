AFIP Groovy
===========

AFIP Groovy is the grooviest version of the security-oriented static code analyzer. You can point any Grails git repository to
it and it will scan it.

These are the problems the scanner finds.

* BadConfiguration: 'codec' set to 'none' in Config.groovy.
* BadEncoding: old style JSP encodings on .gsp files, which may be vulnerable to XSS.
* DefaultURLMappings: URL mappings which leave every controller on the server open.
* HardcodedCredentials: pretty self-explanatory.
* MassAssignments: creation of objects via a user-supplied dictionary.
* OpenRedirect: redirections which may be tampered by an attacker.
* PathTraversal: reading from a path which may be modified by a malicious user.
* ReflectedXSS: reflected cross site scriptings.
* RemoteCodeExecution: shell commands which may be provided by an attacker.
* SqlInjection: will try to detect string concatenations in pure SQL.
* WeakCrtypto: usage of MD5, SHA1, and the like.
* XmlExternalEntities: dangerous usage of an XML parser.

## Docker image

You can build the docker image as follows:

```bash
docker build -t afip-scanner .
```

You can run the AFIP Playground in a container:

```bash
docker run --env-file env.list -p 8080:8080 -d afip-scanner
```

Where the *env.list* file must contain the github keys to access your repositories.


Who should I ask about this?
=====================================================
You can contact Joaquin or Philippe at joaquin.pereyra@mercadolibre.com or philippe.clavier@mercadolibre.com
