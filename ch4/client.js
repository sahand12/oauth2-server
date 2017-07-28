const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const url = require('url');
const qs = require('qs');
const queryString = require('querystring');
const randomString = require('randomstring');
const {join} = require('path');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

app.set('view engine', 'pug');
app.set('views', join(__dirname, 'files', 'client'));

app.use('/', express.static(join(__dirname, 'files', 'protected-resource')));

// Authorization server information
const authServerConfig = {
  authorizationEndPoint: 'http://localhost:9001/authorize',
  tokenEndPoint: 'http://localhost:9001/token',
  revocationEndPoint: 'http://localhost:9001/revoke',
  registrationEndPoint: 'http://localhost:9001/register',
  userInfoEndPoint: 'http://localhost:9001/userinfo'
};

const clientConfig = {
  client_id: 'oauth-client-1',
  client_secret: 'oauth-client-secret-1',
  redirect_uris: ['http://localhost:9000/callback'],
  scope: 'movies foods music'
};

const favoritesApiEndPoint = 'http://localhost:9002/favorites';

let state = null;

let access_token = null;
let refresh_token = null;
let scope = null;

app.get('/', (req, res) => res.render('index', {access_token, refresh_token, scope}));

app.get('/authorize', (req, res, next) => {
  access_token = null;
  refresh_token = null;
  scope = null;
  state = randomString.generate();

  const authorizeUrl = url.parse(authServerConfig.authorizationEndPoint, true);
  delete authorizeUrl.search;
  authorizeUrl.query.response_type = 'code';
  authorizeUrl.query.scope = client.scope;
  authorizeUrl.query.client_id = client.client_id;
  authorizeUrl.query.redirect_uri = client.redirect_uris[0];
  authorizeUrl.query.state = state;

  console.log(`redirect: ${url.format(authorizeUrl)}`);
  return res.redirect(url.format(authorizeUrl));
});

app.get('/callback', (req, res, next) => {
  // It's an error message, act accordingly
  if (req.query.error) {
    return res.render('error', {error: req.query.error});
  }

  const responseState = req.query.state;
  if (responseState !== state) {
    console.log(`State DOES NOT MATCH: expected: ${state} but got ${responseState}`);
    return res.render('error', {error: 'state value did not match'});
  } else {
    console.log(`State value matches: expected ${state} got ${responseState}`);
  }

  const code = req.query.code;
  const formData = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: client.redirect_uris[0]
  };
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Authorization': `Basic ${new Buffer(queryString.escape(client.client_id) + ':' + queryString.escape(client.client_secret)).toString('base64')}`,
  };

  axios.post(authServerConfig.tokenEndPoint,formData, {headers})
    .then(response => {

      console.log('axios response from token end point', response.data);
      if (response.status >= 200 && response.status < 300) {
        const body = response.data;
        access_token = body.access_token;
        console.log(`Got access token: ${access_token}`);

        if (body.refresh_token) {
          refresh_token = body.refresh_token;
          console.log(`Got refresh token: ${refresh_token}`);
        }

        scope = body.scope;
        console.log('Got scope: ${scope}');
        return res.render('index', {access_token, refresh_token, scope});
      }

      return res.render('error', {error: `Unable to fetch access token, server response: ${response.status}`});
    });
});

app.get('/favorites', (req, res) => {
  const headers = {
    Authorization: `Bearer ${access_token}`,
    'Content-Type': 'application/x-www-form-urlencoded'
  };

  axios.get(favoritesApiEndPoint, {headers})
    .then(response => {
      if (response.status >= 200 && response.status < 300) {
        const body = response.data;
        console.log(`Got data: ${body}`);
        return res.render('favorites', {scope, body});
      }
      return res.render('favorites', {scope, data: {user: '', favorites: {movies: [], foods: [], music: []}}});
    });
});

app.use('/', express.static(join(__dirname, 'files', 'client')));

const server = app.listen(9000, 'localhost', () => {
  const host = server.address().address;
  const port = server.address().port;

  console.log(`Client server is listening at http://${host}:${port}`);
});
