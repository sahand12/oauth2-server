'use strict';
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const url = require('url');
const qs = require('qs');
const queryString = require('querystring');
const randomString = require('randomstring');
const { join } = require('path');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.set('view engine', 'pug');
app.set('views', join(__dirname, 'files', 'client'));

// Authorization server information
const authServerInfo = {
  authorizationEndPoint: 'http://localhost:9001/authorize',
  tokenEndPoint: 'http://localhost:9001/token',
  revocationEndPoint: 'http://localhost:9001/revoke',
  registerEndPoint: 'http://localhost:9001/register',
  userInfoEndPoint: 'http://localhost:9001/userinfo',
};

// client information
const clientInfo = {
  client_id: 'oauth-client-1',
  client_secret: 'oauth-client-1-secret',
  redirect_uris: ['http://localhost:9000/callback'],
  scope: 'movies foods music'
};

// Protected resource url
const favoritesApi = 'http://localhost:9002/favorites';

let state = null;
let accessToken = null;
let refreshToken = null;
let scope = null;

app.get('/', (req, res) => res.render('index', {
  accessToken,
  refreshToken,
  scope
}));

app.get('authorize', (req, res) => {
  
  accessToken = null;
  refreshToken = null;
  scope = null;
  state = randomString.generate();
  
  const authorizeUrl = formatResponseUrl(
    authServerInfo.authorizationEndPoint,
    {
      response_type: 'code',
      scope: client.scope,
      client_id: client.client_id,
      redirect_uri: client.redirect_uris[0],
      state
    }
  );
  
  console.log(`redirect: ${authorizeUrl}`);
  return res.redirect(authorizeUrl);
});

app.get('/callback', (req, res, next) => {
  
  // It's an error response, act accordingly
  if (req.query.error) {
    return res.render('error', { error: req.query.error });
  }
  
  const responseState = req.query.state;
  if (responseState !== state) {
    console.log(`State DOES NOT MATCH: expected ${state} but got ${responseState}`);
    return res.render('error', { error: 'State value did not match' });
  }
  console.log(`State valued matches: expected ${state} and got ${responseState}`);
  
  const code = req.query.code;
  const formData = qs.stringify({
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirect_uris[0]
  });
  const authHeader = 'Basic ' +
    new Buffer(
      queryString.escape(client.client_id) +
      ':' +
      queryString.escape(client.client_secret)
    ).toString('base64');
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': authHeader,
  };
  
  console.log(`Requesting access token for code ${code}`);
  
  // Make the request to authorization server
  axios({
    method: 'post',
    url: authServerInfo.tokenEndPoint,
    data: formData,
    headers
  })
    .then(handleResponse)
    .catch(next);
  
  function handleResponse(response) {
    if (response.status >= 200 && response.status < 300) {
      
      const body = JSON.parse(data);
      
      accessToken = body.access_token;
      console.log(`Got access Token ${accessToken}`);
      
      if (body.refresh_token) {
        refreshToken = body.refresh_token;
        console.log(`Got refresh token ${refreshToken}`);
      }
      
      scope = body.scope;
      console.log(`Got scope: ${scope}`);
      
      return res.render('index', { accessToken, refreshToken, scope });
    }
    else {
      return res.render('error', { error: `Unable to fetch access token, server response code ${response.status}` });
    }
  }
});

app.get('/favorites', (req, res, next) => {
  axios.get({
    url: favoritesApi,
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': `Bearer ${accessToken}`
    }
  })
    .then(response => {
      if (response.status >= 200 && response.status < 300) {
        const body = JSON.parse(response.data);
        console.log(`Got data ${body}`);
        return res.render('favorites', { scope, data: body });
      }
      else {
        return res.render('favorites',{
          scope,
          data: {
            user: '',
            favorites: { movies: [], foods: [], music: [] }
          }
        });
      }
    })
    .catch(next);
});

function formatResponseUrl (url, query, hash) {
  const parsedUrl = url.parse(url, true);
  delete parsedUrl.search;
  parsedUrl.query = Object.assign({}, parsedUrl.query || {}, query);
  hash ? parsedUrl.hash = hash : '';
  return url.format(parsedUrl);
}

app.use('/', express.static(join(__dirname, 'files', 'client')));

const server = app.listen('9000', 'localhost', () => {
  const host = server.address().address;
  const port = server.address().port;
  console.log(`OAuth Client Server is listening at http://${host}:${port}`);
});