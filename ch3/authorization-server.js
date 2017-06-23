const express = require('express');
const url = require('url');
const bodyParser = require('body-parser');
const randomString = require('randomstring');
const nosql = require('nosql').load('./database.nosql');
const queryString = require('querystring');
const _ = require('lodash');
_.string = require('underscore.string');
const {join} = require('path');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

app.set('view engine', 'pug');
app.set('views', join(__dirname, 'files', 'authorization-server'));
app.set('json spaces', 4);

// authorization server information
const authServerConfig = {
  authorizationEndPoint: 'http://localhost:9001/authorize',
  tokenEndPoint: 'http://localhost:9001/token'
};

// client information
const clients = [
  {
    client_id: 'oauth-client-1',
    client_secret: 'oauth-client-secret-1',
    redirect_uris: ['http://localhost:9000/callback'],
    scope: 'foo bar'
  }
];

const codes = {};
const requests = {};

const getClient = clientId => _.find(clients, client => client.client_id === clientId);

app.get('/', (req, res) => res.render('index', {clients, authServerConfig}));

app.get('/authorize', (req, res) => {

  // client_id must be in the request query
  const client = getClient(req.query.client_id);
  let requestScope;

  if (!client) {
    console.log(`Unknown client ${req.query.client_id}`);
    return res.render('error', {error: 'Unknown client'});
  } else if (client.redirect_uris.indexOf(req.query.redirect_uri) === -1) {
    console.log(`Mismatched redirect URI, expected ${client.redirect_uris} but got ${req.query.redirect_uri}`);
    return res.render('error', {error: 'Invalid redirect URI'});
  } else {
    requestScope = req.query.scope ? req.query.scope.split(' ') : undefined;
    const clientScope = client.scope ? client.scope.split(' ') : undefined;
    if (_.difference(requestScope, clientScope).length > 0) {
      // client asked for a scope it couldn't have
      const urlParsed = url.parse(req.query.redirect_uri);
      delete urlParsed.search;
      urlParsed.query = urlParsed.query || {};
      urlParsed.query.error = 'invalid_scope';
      return res.redirect(url.format(urlParsed));
    }
  }

  const reqId = randomString.generate(8);

  // authorization grant code
  requests[reqId] = req.query;

  return res.render('approve', {client, reqId, scope: requestScope});
});

app.get('/approve', (req, res) => res.render('approve', {client: {}}));
app.post('/approve', (req, res) => {
  const reqId = req.body.reqId;
  const query = requests[reqId];
  delete requests[reqId];

  if (!query) {
    // There was no matching saved request, this is an error
    return res.render('error', {error: 'No matching authorization request'});
  }

  if (req.body.approve) {
    if (query.response_type === 'code') {
      // user approved access
      const code = randomString.generate(8);
      const user = req.body.user;

      const scope = Object.keys(req.body)
        .filter(param => /^scope_/.test(param))
        .map(param => param.slice('scope_'.length));
      const client = getClient(query.client_id);
      const clientScope = client.scope ? client.scope.split(' ') : undefined;

      if (_.difference(scope, clientScope).length > 0) {
        const urlParsed = url.parse(query.redirect_uri);
        delete urlParsed.search;
        urlParsed.query = urlParsed.query || {};
        urlParsed.query.error = 'invalid_scope';
        return res.redirect(url.format(urlParsed));
      }

      // save the code and request for later use
      codes[code] = {authorizationEndPointRequest: query, scope, user};

      const urlParsed = url.parse(req.query.redirect_uri);
      delete urlParsed.search;
      urlParsed.query = urlParsed.query || {};
      urlParsed.query.code = code;
      urlParsed.query.state = query.state;
      return res.redirect(url.format(urlParsed));
    } else {
      // we got a response type we don't understand
        const urlParsed = url.parse(req.query.redirect_uri);
        delete urlParsed.search;
        urlParsed.query = urlParsed.query || {};
        urlParsed.query.error = 'unsupported_response_type';
        return res.redirect(url.format(urlParsed));
    }
  } else {
    // user denied access
    const urlParsed = url.parse(req.query.redirect_uri);
    delete urlParsed.search;
    urlParsed.query = urlParsed.query || {};
    urlParsed.query.error = 'access_denied';
    return res.redirect(url.format(urlParsed));
  }
});

app.post('/token', (req, res) => {
  const auth = req.headers['authorization'];
  let clientId, clientSecret;

  if (auth) {
    // parse the auth
    [clientId, clientSecret] = new Buffer(auth.slice('basic '.length), 'base64')
      .toString()
      .split(':')
      .map(str => queryString.unescape(str));
  }

  // otherwise, check the post body
  if (req.body.client_id) {
    if (clientId) {
      // if we've already seen the client's credentials in the authorization header, this is an error.
      console.log(`client attempted to authenticate with multiple methods.`);
      return res.status(401).json({error: 'invalid_client'});
    }

    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }

  const client = getClient(clientId);
  if (!client) {
    console.log(`Unknown client: ${clientId}`);
    return res.status(401).json({error: 'invalid_client'});
  }

  if (client.client_secret !== clientSecret) {
    console.log(`Mismatched client secret, expected ${client.client_secret} but got ${clientSecret}`);
    return res.status(401).json({error: 'invalid_client'});
  }

  if (req.body.grant_type === 'authorization_code') {
    const code = codes[req.body.code];
    if (code) {
      delete codes[req.body.code]; // burn our code, it's been used.

      if (code.authorizationEndPointRequest.client_id  === clientId) {

        const accessToken = randomString.generate();
        let clientScope = null;
        if (code.scope) {
          clientScope = code.split(' ');
        }

        nosql.insert({access_token: accessToken, client_id: clientId, scope: clientScope});
        console.log(`Issuing access token ${accessToken}`);
        console.log(`with scope: ${clientScope}`);

        const tokenResponse = {
          access_token: accessToken,
          token_type: 'Bearer',
          scope: clientScope
        };

        console.log(`Issued tokens for code ${req.body.code}`);
        return res.status(200).json(tokenResponse);
      }
      else {
        console.log(`Client mismatch, expected ${code.authorizationEndPointRequest.client_id} but got ${clientId}`);
        return res.status(400).json({error: 'invalid_grant'});
      }
    }
    else {
      // Unknown code
      console.log(`Unknown code, ${req.body.code}`);
      return res.status(400).json({error: 'invalid_grant'});
    }
  }
  else {
    console.log(`Unknown grant type ${req.body.grant_type}`);
    return res.status(400).json({error: 'unsupported_grant_type'});
  }
});

app.use('/', express.static(join(__dirname, 'files', 'authorization-server')));

// clear the database on startup
nosql.clear();

const server = createServer(app, undefined, 9001);

function createServer (app, host = 'localhost', port = 3000) {
  const server = app.listen(port, host, () =>
    console.log(`OAuth Authorization Server is running at http://${server.address().address}:${server.address().port}`));
  
  return server;
}
