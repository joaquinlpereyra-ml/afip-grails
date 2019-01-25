import express from 'express';
import bodyParser from 'body-parser';
import axios from 'axios';
import React from 'react';
import { renderToString } from 'react-dom/server';
import PageNotFound from '../client/components/PageNotFound.jsx';
import html from '../client/html.js';
import dataStore from './helpers/DataStore.js';
import vulntypes from './helpers/vulntypes.js';

const app = express();

app.use(express.static(__dirname +'./../client/static')); //serves the index.html

// Use middleware to parse the request body and place the result in req.body of your route.
app.use(bodyParser.json());

const scannerURL = 'http://scanner:8080'
const playgroundURL = 'http://playground:8080'

app.get('/ping', function (req, res) {
  res.send('pong');
});

app.get('/api/getvulns', function (req, res) {
	console.log('[GET] /api/getvulns - Getting Vuln Types');
  const data = {
    type: "vuln-types",
    attributes: {types: vulntypes}
  }
  res.send(data)
});

app.post('/api/sendcode', function (req, res) {
  console.log('[POST] /api/sendcode - Request Snippet Analisys');
  let body = req.body;
  body.data.attributes.url = playgroundURL + '/api/results'
  const url = scannerURL + '/playground';
  axios.post(url, body)
  .then( response => {
    console.log('|- Snippet Analisys Started');
    res.status(response.status).send(response.data);
  }).catch( error => {
    console.log('|- ERROR: Request to AFIP Scanner failed');
    res.status(500).send('Request to AFIP Scanner failed');
  })
});

app.get('/api/results', function (req, res) {
  console.log(`[GET] /api/results - Get All Snippet Analisys Results`);
  const results = dataStore.list();
  res.status(200).send({results: results});
});

app.get('/api/results/:id', function (req, res) {
  console.log(`[GET] /api/results/${req.params.id} - Get Snippet Analisys Result`);
  const id = req.params.id;
  const result = dataStore.get(id)
  if(result) {
    console.log('|- Result Returned');
    res.status(200).send(result);
  } else {
    console.log('|- Result Not Found');
    const noContent = JSON.stringify({type: 'no-content'});
    res.status(200).send(noContent);
  }
});

app.post('/api/results', function (req, res) {
  console.log('[POST] /api/results - Receive Snippet Analisys Results');
  const body = req.body;
  console.log(`|- Result Stored [ID:${body.id}]`);
  // Save resuts to be accessed by a request from the client
  dataStore.add(body);
  res.sendStatus(200);
});

app.get('*', (req, res) => {
  const body = renderToString(<PageNotFound/>);
  const title = '404 - Page Not Found';
  res.send(
    html({
      body,
      title
    })
  );
});

const server = app.listen(8080, function () {
  const port = server.address().port;
  console.log('App listening at http://localhost:%s', port);
});