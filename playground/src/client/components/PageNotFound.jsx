import React, { Component } from 'react';

// import styles from './static/scss/application.scss';

class PageNotFound extends Component {
  render() {
    return (
      <div className="PageNotFound">
        <header className="App-header row">
          <img className="logo float-left" src="img/logo.png"/>
          <h1 className="App-title float-left">The AFIP Playground</h1>
        </header>
        <h1>404</h1>
        <p>Sorry, the page you're looking for cannot be found</p>
        <a href="javascript:window.open(window.location.origin,'_self');">Go back to our homepage</a>
      </div>
    );
  }
}

export default PageNotFound;
