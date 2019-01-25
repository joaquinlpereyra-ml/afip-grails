# AFIP Playground

![technology Node.js](https://img.shields.io/badge/technology-node-green.svg)

The AFIP Playground is a magical place where you can test out you code against several vulnerabilities.


## Docker image

You can build the docker image as follows:

```bash
docker build -t afip-playground .
```

You can run the AFIP Playground in a container:

```bash
docker run -p 8080:8080 -d afip-playground
```

## Output

The AFIP Scanner relies on taint analysis to find vulnerabilities. The concept behind it is that any variable that can be modified by an outside user poses a potential security risk.

In this sense we can define three types of variables:
- Tainted: A variable that carries user modified data
- Vulnerable: If the tainted variable gets passed to a sink (vulnerable function) without first being sanitized it is flagged as a vulnerability
- Cleaned: When a tainted variable is sanitised it is flagged as a cleaner

The AFIP Playground points these cases for us in the code for a specific vulnerability.

## Usage

1. Load a snippet of code you want to analyze.
(You can use the Example button to load an example snippet for the selected vulnerability)

2. Select a vulnerability against which you want to test your code.

3. Analyze the code and see the results obtained!

## Questions

* [philippe.clavier@mercadolibre.com](philippe.clavier@mercadolibre.com)

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License [here](http://www.apache.org/licenses/LICENSE-2.0).
