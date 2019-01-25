const express = require('express');
const app = express();
const port = 8000;

const bodyParser = require('body-parser');
app.use(bodyParser.json());

/**
 * This module is a simple server provided just as an example.
 * It is NOT IN ANY WAY SUPPORTED FOR PRODUCTION.
 * We provide it as a simple way to see a simple implementation
 * of a server connecting to the scanner.
 * You are free to provide it with several capabilities: a persistence layer,
 * false positive support, fault tolerance and many other goodies.
 *
 * Documentation of what each method does is pretty extensive in case you do
 * want to create an API for the scanner.
*/

// A queue holds the scans which have not been grabbed by a scanner yet.
// The scanner works asynchronously: you can register as many scans
// as you want in this API, the scanner will retrieve one at a time
// and return the results.
let queue = [];

// This is NOT a REST API. Heck I challenge you to make something more
// stateful than this. This scans object holds the results returned by
// the scanner. In production, this should be replaced by a database
// of some kind.
let scans = {};

// Recieves requests of scans.
// This will queue a scan. Be mindful of the "commitURL" key:
// this will tell the scanner where to 'commit' the scan
// Once a scanner commits, the scan is removed from the queue
// and no other scanner will grab it.
// This makes coordination possible when there are several instances
// of scanners running
app.post('/scans/queue', (req, res) => {
    let date = new Date();
    let hash = Math.random().toString(36).substring(2, 15);
    let repositoryURL = req.body.data.attributes.repositoryURL;
    let tags = req.body.data.attributes.tags;
    tags = tags ? tags : [];
    let queuedScan = {
        "id": hash,
        "type": "queuedScan",
        "attributes": {
            "repositoryURL": repositoryURL,
            "commitURL": `http://example-api:8000/scans/queue/${hash}`,
            "date": date,
            "tags": tags
        }
    };
    let response = {
        "data": {
            "type": "acceptedScan",
            "attributes": {
                "scanID": hash
            }
        }
    };
    console.log(`New Scan Requested - Hash: ${hash} - Repository URL: ${repositoryURL}`);
    queue.push(queuedScan);
    res.send(response);
});

// Responds with the queue of scans
// The scanner is configured to request the queue from this path.
// The "callback" key is important here, it tells the scanner where
// to POST the results
app.get('/scans/queue', (req, res) => {
    let date = new Date();
    let response = {
        "data": {
            "id": date,
            "type": "queue",
            "attributes": {
                // The groovy scanner takes scans from the groovy queued
                // You may build new scanners and simply request the queue
                // and take scans from the new language queue.
                // This allows you to build new scanners and connect them
                // to just a single API quite easily.
                "groovy": queue
            }
        },
        "meta": {
            "callback": "http://example-api:8000/scans/results",
            // The test probe is a simple request sent from the scanner
            // to the callback URL to make sure the callback URL
            // is available. This is disabled by default, but may
            // be useful for fault tolerance.
            "disableTestProbe": true
        }
    };
    if (queue[0]) {
        scans[queue[0].id] = {
            "status": "Sent to scanner"
        };
    };
    res.send(JSON.stringify(response));
});

// Accepts commits from scans
app.put('/scans/queue/:id', (req, res) => {
    // The scanner commits to take the scanning of the queued scans
    console.log("Commit From Scanner - ID:", req.params.id);
    scans[req.params.id] = {
        "status": "running"
    };
    queue.pop();
    res.sendStatus(200);
});

// Receives scans results from scanner
app.post('/scans/results', (req, res) => {
    console.log("Results From Scanner:", req.body);
    let errors = req.body.errors;
    if (errors) {
        scans[req.body.meta.hash] = {
            "status": "failed",
            "errors": errors
        };
    } else {
        scans[req.body.meta.hash] = {
            "status": "finished",
            "results": req.body.data
        };
    }
    res.sendStatus(200);
});

// Responds with the result of an specific scan
app.get('/scans/results/:id', (req, res) => {
    res.json(scans[req.params.id]);
});

// Responds with the results of all the scans
app.get('/scans/results', (req, res) => {
    res.json(scans);
});

app.listen(port, (err) => {
    if (err) {
        return console.log('something bad happened', err);
    }
    console.log(`server is listening on ${port}`);
});
