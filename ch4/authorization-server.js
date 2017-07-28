const express = require('express');
const url = require('url');
const bodyParser = require('body-parser');
const randomString = require('randomstring');
const nosql = require('nosql').load('database.nosql');
const queryString= require('querystring');
const qs = require('qs');
const _ = require('lodash');
_.string = require('underscore.string');
const {join} = require('path');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

app.set('view engine', 'pug');
app.set('views', join(__dirname, 'files', 'authorization-server'));
app.set('json spaces', 4);

const authServerConfig = {
  authorizationEndPoint: 'http://localhost:9001/authroize',
  tokenEndPoint: 'http://localhost:9001/token'
};

const clients = [
  {
    client_id: 'oauth-client-1',
    client_secret: 'oauth-client-secret-1',
    redirect_uris: ['http://localhost:9000/callback'],
    scope: 'movies foods music'
  }
];

const userInfos = {
  alice: {
    sub: '9XE3-JI34-00132A',
    preferred_username: 'alice',
    name: 'Alice',
    email: 'alice.wonderland@example.com',
    email_verified: true
  },
  bob: {
    sub: '1ZT5-0E63-57383B',
    preferred_username: 'bob',
    name: 'Bob',
    email: 'bob.loblob@example.net',
    email_verified: false
  },
  carol : {
    sub: 'F5Q1-l6lGG-959FS',
    preferred_username: 'carol',
    name: 'Carol',
    email: 'carol.lewis@example.net',
    email_verified: true,
    username: 'clewis',
    password: 'user password!'
  }
};

const codes = {};
const request = {};

const getClient = id => {
  const [found] = clients.filter(cl => cl.client_id === id);
  return found ? found : null;
};

const getUser = username => {
  for (let user in userInfos) {
    if (userInfos.hasOwnProperty(user)) {
      if (user.username === username || user.preferred_username === username) {
        return user;
      }
    }
  }
  return null;
};

app.get('/', (req, res) => res.render('index', {clients, authServerConfig}));

app.get('/authorize', (req, res) => {
  const client = getClient(req.query.client_id);
  if (!client) {
    console.log(`Unknown client ${req.query.client_id}`);
    return res.render('error', {error: 'Unknown client'});
  }
  else if (client.redirect_uris.indexOf(req.query.redirect_uri) === -1) {
    console.log(`Mismatched redirect URI, expected: ${client.redirect_uris} got ${req.query.redirect_uri}`);
    return res.render('error', {error: 'Invalid redirect URI'});
  }

  req.query.scope = decodeURIComponent(req.query.scope);
  const requestScope = req.query.scope ? req.query.scope.split(' ') : [];
  const clientScope = client.scope ? client.scope.split(' ') : [];

  // client asked for a scope it couldn't have
  if (_.difference(requestScope, clientScope).length > 0) {
    const urlParsed = url.parse(req.query.redirect_uri);
    delete urlParsed.search;
    urlParsed.query = urlParsed.query || {};
    urlParsed.query.error = 'invalid scope';
    return res.redirect(url.format(urlParsed));
  }

  const reqId = randomString.generate(8);
  requests[reqId] = req.query;

  return res.render('approve', {client, reqId, scope: requestScope});
});

app.post('/approve', (req, res) => {
  const reqId = req.body.reqId;
  const query = requests[reqId];
  delete requests[reqId];

  // There was no matching saved request, this is an error
  if (typeof query === 'undefined') {
    return res.render('error', {error: 'No matching authorization request'});
  }

  // User rejected the client to have access the specified scopes
  if (!req.body.approve) {
    const urlParsed = url.parse(query.redirect_uri);
    delete urlParsed.search;
    urlParsed.query = urlParsed.query || {};
    urlParsed.query.error = 'access denied';
    return res.redirect(url.format(urlParsed));
  }

  // User approved the client
  if (query.response_type === 'code') {
    const code = randomString.generate(8);
    const user = req.body.user;
    const scope = Object.keys(req.body)
      .filter(param => /^scope_/.test(param))
      .map(param => param.slice('scope_'.length));

    const client = getClient(query.client_id);
    const clientScope = client.scope ? client.scope.split(' ') : [];

    // Client asked for a scope it couldn't have
    if (_.difference(scope, clientScope).length > 0) {
      const urlParsed = url.parse(query.redirect_uri);
      delete urlParsed.search;
      urlParsed.query = urlParsed.query || {};
      urlParsed.query.error = 'invalid scope';
      return res.redirect(url.format(urlParsed));
    }

    // save the code and request for later
    codes[code] = {authorizationEndPointRequest: query, scope, user};

    const urlParsed = url.parse(query.redirect_uri);
    delete urlParsed.search;
    urlParsed.query = urlParsed.query || {};
    urlParsed.query.code = code;
    urlParsed.query.state = query.state;
    return res.redirect(url.format(urlParsed));
  }
  else if (query.response_type === 'token') {
    let user = req.body.user;
    const scope = Object.keys(req.body)
      .filter(param => /^scope_/.test(param))
      .map(param => param.slice('scope_'.length));

    const client = getClient(query.client_id);
    const clientScope = client.scope ? client.scope.split(' ') : [];
    // Client asked for a scope it couldn't have
    if (_.difference(scope, clientScope).length > 0) {
      const urlParsed = url.parse(query.redirect_uri);
      delete urlParsed.search;
      urlParsed.query = urlParsed.query || {};
      urlParsed.query.error = 'invalid scope';
      return res.redirect(url.format(urlParsed));
    }

    user = userInfos[user];
    if (!user) {
      console.log(`Unknown user ${user}`);
      return res.status(500).render('error', {error: `Unknown user ${user}`});
    }

    console.log(`User ${user}`);
    const token_response = generateTokens(req, res, query.client_id, user, scope);
    const urlParsed = url.parse(query.redirect_uri);
    delete urlParsed.search;
    if (query.state) {
      token_response.state = query.state;
    }
    urlParsed.hash = qs.stringify(token_response);
    return res.redirect(url.format(urlParsed));
  }
  else {
    // We got a response type we don't understand
    const urlParsed = url.parse(query.redirect_uri);
    delete urlParsed.search;
    urlParsed.query = urlParsed.query || {};
    urlParsed.query.error = 'unsupported response type';
    return res.redirect(url.format(urlParsed));
  }
});

const generateTokens = (req, res, clientId, user, scope, nonce, generateRefreshToken) => {
  const accessToken = randomString.generate();
  const refreshToken = generateRefreshToken ? randomString.generate() : null;

  nosql.insert({
    access_token: accessToken,
    client_id: clientId,
    scope,
    user: user.preferred_username
  });

  if (refreshToken) {
    nosql.insert({
      refresh_token: refreshToken,
      client_id: clientId,
      scope,
      user
    });
  }

  console.log(`Issuing access token ${accessToken}`);
  if (refreshToken) {
    console.log(`and refresh token ${refreshToken}`);
  }
  console.log(`with scope ${scope}`);

  const clientScope = scope ? scope.join(' ') : null;
  const tokenResponse = {
    access_token: accessToken,
    token_type: 'Bearer',
    refresh_token: refreshToken,
    scope: clientScope
  };

  return tokenResponse;
};

app.post('/token', (req, res, next) => {
  const auth = req.headers['authorization'];
  let clientId, clientSecret;

  if (auth) {
    // check the auth header
    [clientId, clientSecret] = new Buffer(auth.slice('basic '.length), 'base64')
      .toString()
      .split(':')
      .map(str => queryString.unescape(str));
  }

  // otherwise, check the post body
  if (req.body.client_id) {

    // if we've already seen the client's credentials in the authorization header, this is an error
    if (clientId) {
      console.log('Client attempted to authenticate with multiple methods');
      return res.status(401).json({error: 'invalid client'});
    }

    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }

  const client = getClient(clientId);
  if (!client) {
    console.log(`Unknown client ${clientId}`);
    return res.status(401).json({error: 'invalid client'});
  }

  if (client.client_secret !== clientSecret) {
    console.log(`Mismatched client secret, expected ${client.client_secret} but got ${clientSecret}`);
    return res.status(401).json({error: 'invalid client'});
  }

  if (req.body.grant_type === 'authorization_code') {
    const code = codes[req.body.code];
    if (!code) {
      console.log(`Unknown code ${req.body.code}`);
      return res.status(400).json({error: 'invalid grant'});
    }

    // burn our code, it's been used
    delete codes[req.body.code];
    if (code.authorizationEndPointRequest.client_id !== clientId) {
      console.log(`Client mismatch, expected ${code.authorizationEndPointRequest.client_id} but got ${clientId}`);
      return res.status(400).json({error: 'invalid grant'});
    }

    const user = userInfos[code.user];
    if (!user) {
      console.log(`Unknown user ${code.user}`);
      return res.status(500).render('error', {error: `Unknown user ${code.user}`});
    }

    console.log(`User ${user}`);
    const tokenResponse = generateTokens(req, res, clientId, user, code.scope, code.authorizationEndPointRequest.nonce, true);

    console.log(`Issued token for code ${req.body.code}`);
    return res.status(200).json(tokenResponse);
  }
  else if (req.body.grant_type === 'client_credentials') {
    const scope = req.body.scope ? req.body.scope.split(' ') : undefined;
    const client = getClient(query.client_id);
    const clientScope = client.scope ? client.scope.split(' ') : undefined;

    // client asked for a scope it couldn't have
    if (_.difference(scope, clientScope).length > 0) {
      return res.status(400).json({error: 'invalid scope'});
    }

    const accessToken = randomString.generate();
    const tokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      scope: scope.join(' ')
    };
    nosql.insert({
      access_token: accessToken,
      client_id: clientId,
      scope
    });
    console.log(`Issuing access token ${accessToken}`);
    return res.status(200).json(tokenResponse);
  }
  else if (req.body.grant_type === 'refresh_token') {
    nosql.all(
      token => token.refresh_token === req.body.refresh_token, // query
      (err, tokens) => {                                        // response
        if (err || tokens.length !== 1) {
          console.log('No matching token was found');
          return res.status(401).end();
        }

        const [token] = tokens;
        if (token.client_id !== clientId) {
          console.log(`Invalid client using a refresh token, expected ${token.client_id} but got ${clientId}`);
          nosql.remove(
            found => found === token,
            () => {}
          );
          return res.status(400).end();
        }

        console.log(`We found a matching token ${req.body.refresh_token}`);
        const accessToken = randomString.generate();
        const tokenResponse = {
          access_token: accessToken,
          token_type: 'Bearer',
          refresh_token: req.body.refresh_token
        };

        nosql.insert({
          access_token: accessToken,
          client_id: clientId
        });

        console.log(`Issuing access token ${accessToken} for refresh token ${req.body.refresh_token}`);

        return res.status(200).json(tokenResponse);
      }
    );
  }
  else if (req.body.grant_type === 'password') {
    const username = req.body.username;
    const user = getUser(username);
    if (!user) {
      console.log(`Unknown user ${req.body.username}`);
      return res.status(401).json({error: 'invalid grant'});
    }

    console.log(`User ${user}`);
    const password = req.body.password;
    if (user.password !== password) {
      console.log(`Mismatched resource owner password, expected ${user.password} but got ${password}`);
      return res.status(401).json({error: 'invalid grant'});
    }

    const {scope} = req.body;
    const tokenResponse = generateTokens(req, res, clientId, user, scope);

    return res.status(200).json(tokenResponse);
  }
  else {
    console.log(`Unknown grant type ${req.body.grant_type}`);
    return res.status(400).json({error: 'unsupported grant type'});
  }
});

app.use('/', express.static(join(__dirname, 'files', 'authorization-server')));

// clear the database
nosql.clear();

const server = app.listen(9001, 'localhost', () => {
  const host = server.address().address;
  const port = server.address().port;

  console.log('Authorization Server is listening at http://${host}:${port}');
});
