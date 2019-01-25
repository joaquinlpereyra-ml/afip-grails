import React, { Component } from 'react';

import axios from 'axios';

import CodeMirror from 'react-codemirror';
import 'codemirror/lib/codemirror.css';
import 'codemirror/mode/groovy/groovy';

import Select from 'react-select';

import { Button, DropdownButton, MenuItem } from 'react-bootstrap';

import snippets from '../static/text/snippets.js';

const customStyles = {
  option: (base, state) => ({
    ...base,
    borderBottom: '1px dotted',
    color: 'black'
  })
}

const about = <div className="output">
  <div>
    <h1>About the Playground</h1>
  </div>
  <div>
    The AFIP Playground is a magical place where you can test out your code against several vulnerabilities. Are you up for the challenge?
    <br/><br/>
    You can use the Example button to load an example snippet for the selected vulnerability.
    <br/><br/>
    The AFIP Scanner relies on taint analysis to find vulnerabilities. The concept behind it is that any variable that can be modified by an outside user poses a potential security risk.
    <br/>
    In this sense we can define three types of variables:
    <br/>
    <ul>
      <li>Tainted: A variable that carries user modified data</li>
      <li>Vulnerable: If the tainted variable gets passed to a sink (vulnerable function) without first being sanitized it is flagged as a vulnerability</li>
      <li>Cleaned: When a tainted variable is sanitised it is flagged as a cleaner</li>
    </ul>
  </div>
</div>;

const scanInProgress = <div className="output">
  <div>
    <h1>Scan In Progress</h1>
  </div>
</div>;

const scanFailed = <div className="output">
  <div>
    <h1>Scan Failed</h1>
  </div>
  Check your syntax!
</div>;

class App extends Component {

	constructor(props) {
    super(props);

    this.state = {
      code: '',
      output: 'about',
      previousOutput: 'about',
      scannedCode: '',
      resultsFor: '',
      vulnTypes: [],
      scanInPrgoress: false,
      requestCounter: 0,
      scanID: '',
      timer: 0
    }

    this.checkForResult = this.checkForResult.bind(this);
  }

  componentDidMount(){
  	const requestURL = window.location.origin + '/api/getvulns';
    axios.get(requestURL)
    .then(response => {
    	this.setState({vulnTypes: response.data.attributes.types});
    });
  }

	sendCode(){
    console.log('Sending Code to AFIP Scanner');
		const requestURL = window.location.origin + '/api/sendcode';
    const requestID = guid();
    const vulnType = this.state.activeVuln;
    const code = this.state.code;
    const responseUrl = window.location.origin + '/api/results';
    const data = snippetAnalyserJSON(requestID, vulnType, code, responseUrl);
    const config = postConfig();
    axios.post(requestURL, data, config)
    .then(response => {
      const results = response.data;
      if (results.type == 'snippet-accepted' && requestID == results.id && vulnType == results.attributes.vuln) {
        console.log('Snippet Analizer request accepted');
        let timer = setInterval(this.checkForResult, 2000); // Cada 2 seg hago una request
        this.setState({
          output: 'scanInProgress',
          scanInPrgoress: true, 
          scanID: results.id,
          timer: timer,
          requestCounter: 30
        });
      }
    }).catch(error => {
      console.log(error);
    })
  }

  checkForResult(){
    this.getResult()
    .then(results => {
      if(results.type == 'results') {
        console.log('Results received from AFIP Scanner');
        clearInterval(this.state.timer);
        const code = this.state.code;
        const scannedCode = colorLines(code, results.attributes.lines);
        this.setState({
          output: 'results',
          scannedCode: scannedCode,
          resultsFor: results.attributes.vuln,
          scanInPrgoress: false,
          requestCounter: 0, 
          scanID: ''
        });
      } else if (results.type == 'no-content') {
        // count the number of requests made and stop after some time
        const requestCounter = this.state.requestCounter - 1;
        if(requestCounter == 0){
          console.log('Timeout - Results could not be retreived from Scanner');
          clearInterval(this.state.timer);
          this.setState({
            output: 'scanFailed',
            scanInPrgoress: false,
            requestCounter: requestCounter
          });
        } else {
          this.setState({
            requestCounter: requestCounter
          });
        }
      } else if (results.type == 'failed-scan') {
         // end requests
        console.log('For some reason the scan has failed');
        clearInterval(this.state.timer);
        this.setState({
          output: 'scanFailed',
          scanInPrgoress: false,
          requestCounter: 0
        });
      }
      else {
        // end requests
        console.log('For some reason the server is not responding');
        clearInterval(this.state.timer);
        this.setState({
          scanInPrgoress: false,
          requestCounter: 0
        });
      }
    }).catch(error => {
      console.log(error);
    })    
  }

  getResult(){
    const id = this.state.scanID
    const requestURL = window.location.origin + `/api/results/${id}`;
    return axios.get(requestURL)
    .then(response => {
      return response.data
    }).catch(error => {
      console.log(error)
    });
  }

  aboutText(){
    if(this.state.output != 'about'){
      this.setState({ 
        output: 'about',
        previousOutput: this.state.output
      })  
    } else {
      this.setState({ 
        output: this.state.previousOutput,
        previousOutput: 'about'
      })
    }
  }

  loadExample(){
    console.log('Load Example Snippet')
    const exampleSnippet = snippets[this.state.activeVuln] ? snippets[this.state.activeVuln] : ''
    this.setState({
      code: exampleSnippet
    })
    this.cm.codeMirror.setValue(exampleSnippet)
  }

  updateCode(newCode) {
    this.setState({
      code: newCode
    });
  }

  handleSelect(selectedOption) {
    console.log('Vuln Selected:', selectedOption.label );
    this.setState({ activeVuln: selectedOption.label });
  }

  render() {

		const results = <div className="output">
      <div className="row">
        <div className="padding float-left">
          <h1>Results for {this.state.resultsFor}</h1>
        </div>
        <div className="legend-padding result-code">
          <ul>
            <li style={{color: '#DE4A47'}}>red - vulnerable</li>
            <li style={{color: '#F5C036'}}>yellow - tainted</li>
            <li style={{color: '#8CBE78'}}>green - cleaned</li>
          </ul>
        </div>  
      </div>
      <div className="data result-code">
        <ol>
          {this.state.scannedCode}
        </ol>
      </div>
    </div>;

    let output;
    switch(this.state.output) {
    case 'results':
        output = results
        break;
    case 'about':
        output = about
        break;
    case 'scanInProgress':
        output = scanInProgress
        break;
    case 'scanFailed':
        output = scanFailed
        break;        
    }

    const options = this.state.vulnTypes.map( vuln => { return { value: vuln, label: vuln } })

    return (
      <div className="App">
        <header className="App-header row">
          <img className="logo float-left" src="img/logo.png"/>
          <h1 className="App-title float-left">The AFIP Playground</h1>
          <div className="about-button float-left">
            <Button bsSize="xsmall" onClick={this.aboutText.bind(this)}>
              About
            </Button>
          </div> 

          <div className="send-button float-right">
            <Button bsSize="xsmall" onClick={this.loadExample.bind(this)}>
              Example
            </Button>
          </div>
          <div className="send-button float-right">
            <Button bsSize="xsmall" onClick={this.sendCode.bind(this)}>
              Analize Code
            </Button>
          </div>
          <div className="select float-right">
            <Select
              className="no-outline"
              placeholder="Select a vulnerability"
              options={ options } 
              styles={customStyles}
              onChange={this.handleSelect.bind(this)}
              theme={(theme) => ({
                ...theme,
                colors: {
                ...theme.colors,
                  primary25: '#C2CAC0',
                  primary: 'black',
                },
              })}
            />
          </div>
        </header>
        <div>
          <CodeMirror 
            className="codeViewer"
            value={this.state.code} 
            onChange={this.updateCode.bind(this)} 
            options={{lineNumbers: true, mode: 'groovy'}}
            ref={el => this.cm = el} 
          />
        </div>
        {output}
      </div>
    );
  }
}

export default App;

function colorLines(code, results) {
  let color;
  let coloredLines = [];
  const separateIntoLines = code.split("\n");
  const cleanerLines = results.cleaners;
  const taintedLines = results.tainted;
  const vulnerableLines = results.vulnerable;
  separateIntoLines.forEach((line, i) => {
    color = '#C2CAC0' // 'white';
    if(taintedLines.includes(i)){
      color = '#F5C036' // 'yellow';  
    }
    if(vulnerableLines.includes(i)){
      color = '#DE4A47' // 'red';  
    }
    if(cleanerLines.includes(i)){
      color = '#8CBE78' // 'green';  
    }
    coloredLines.push(<li key={i} style={{color: color}}>{line}</li>);
  });
  return coloredLines;
}

function snippetAnalyserJSON (id,vuln,code,url) {
  return JSON.stringify({
    data: {
      type: 'snippet',
      id: id,
      attributes: {
        vuln: vuln,
        code: code,
        url: url   
      }
    }
  });
}

function postConfig(data) {
  return {
    headers: {
      'accept': 'application/json',
      'content-type': 'application/json',
    }
  };
}

function guid() {
  function s4() {
    return Math.floor((1 + Math.random()) * 0x10000)
      .toString(16)
      .substring(1);
  }
  return s4() + s4() +  s4() + s4() + s4() + s4() + s4() + s4();
}