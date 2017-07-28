const express = require('express');
const axios = require('axios');
const url = require('url');
const qs = require('qs');
const queryString = require('querystring');
const randomString = require('randomstring');
const _ = require('lodash');
_.string = require('underscore.string');
const {join} = require('path');

const app = express();

app.set('view engine', 'pug');
app.set('views', join(__dirname, 'files', 'client'));

// Authorization server information
const authServerConfig = {
  authorizationEndPoint: 'http://localhost:9001/authorize',
  tokenEndPoint: 'http://localhost:9001/token'
};

// client information
const client = {
  client_id: 'oauth-client-1',
  client_secret: 'oauth-client-secret-1',
  redirect_uris: ['http://localhost:9000/callback']
};

const protectedResource = 'http://localhost:9002/resource';

let state = null;
let accessToken = null;
let scope = null;

// @TODO: remember to change access_token to accessToken in view file
app.get('/', (req, res) => res.render('index', {accessToken, scope}));

app.get('/authorize', (req, res) => {
  accessToken = null;
  state = randomString.generate();
  const authorizeUrl = buildUrl(authServerConfig.authorizationEndPoint, {
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    state
  });

  console.log(`redirect ${authorizeUrl}`);
  return res.redirect(authorizeUrl);
});

app.get('/callback', (req, res) => {
  if (req.query.error) {
    // it's an error response, act accordingly
    return res.render('error', {error: req.query.error});
  }

  if (req.query.state !== state) {
    console.log(`State DOES NOT MATCH: expected ${state} but got ${req.query.state}`);
    return res.render('error', {error: 'State value did not match'});
  }

  const code = req.query.code;
  const formData = qs.stringify({
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirect_uris[0]
  });
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': `Basic ${encodeClientCredentials(client.client_id, client.client_secret)}`
  };

  axios.post(authServerConfig.authorizationEndPoint, formData, {headers})
    .then(response => {
      if (response.status >= 200 && response.status < 300) {
        const body = JSON.parse(response.data);
        accessToken = body.access_token;
        console.log(`Got access token: ${accessToken}`);
        return res.render('index', {accessToken, scope});
      }
      else {
        return res.render('error', {error: `Unable to fetch access token, server response: ${response.status}`});
      }
    });
});

app.get('/fetch_resource', (req, res) => {

});
