Problems
===============
AFIP outputs problems. This document aims to describe their format to aid the developer.
All problems have the same JSON structure.
There's a list of all the possible 'problemName' values at the bottom of this document.

```json
{ "problemName": {
    "filePath": "the path of the file where the problem was found, eg: $REPO_NAME/controllers/file.groovy"
    "reason": "why is this a problem",
    "solution": "a proposed solution for the problem",
    "code": "the specific line of code where the problem was found",
    "lineNumber": "an APROXIMATED line number where the problme was found",
    "confidence": "a confidence level for the problem",
    "information": "extra information for the problem. this may be an empty string.",
    "referenceURL": "a reference url for the user to find more information about the problem",
    "isVuln": "a boolean indicating whether this is a vulnerability or just a bad practice" }]
} }
```

Vulnerability names 
-------------------------
These are problems which have their 'isVuln' field set to true.

* "Reflected XSS" 

Bad practices names
--------------------------
These are problems which have their 'isVuln' field set to false.

* "Default encoding set to None"
* "Bad Encondig"
* "Unsafe loading of a static resource"
* "Default mappings"
* "Weak Hashing Method"
