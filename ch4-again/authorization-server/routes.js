'use strict';
const dbPromise = require('../db');
const _ = require('lodash');
const url = require('url');
const qs = require('qs');
const randomString = require('randomstring');
const { requests, addRequest } = require('./requests');
const { clients, getClient } = require('./clients');
const { codes, addCode } = require('./codes');
const { authServerInfo } = require('./config');
const { users } = require('./users');

exports.indexRoute = function indexRoute(req, res, next) {
  return res.render('index', { clients, authServer: authServerInfo });
};

exports.authorize = function authorize(req, res, next) {
  
  const client = getClient(req.query.client_id);

  if (!client) {
    console.log(`Unknown client id ${req.query.client_id}`);
    return res.render('error', { error: 'Unknown client id' });
  }
  else if (!client.redirect_uris.includes(req.query.redirect_uri)) {
    console.log(`Mismatched redirect URI, expected ${client.redirect_uris} but got ${req.query.redirect_uri}`);
    return res.render('error', { error: 'Invalid redirect URI' });
  }
  
  const requestScope = req.query.scope ? req.query.scope.split(' ') : undefined;
  const clientScope = client.scope ? client.scope.split(' ') : undefined;
  
  // Client asked for a scope it does not have
  if (_.difference(requestScope, clientScope).length > 0) {
    let responseUrl = formatResponseUrl(req.query.redirect_uri, { error: 'invalid_scope' });
    return res.redirect(responseUrl);
  }
  
  const reqId = randomString.generate(8);
  addRequest(reqId, req.query);

  return res.render('approve', { client, reqId, scope: requestScope });
};

exports.approve = function approve(req, res, next) {

  const reqId = req.body.reqid;
  const query = requests[reqId];
  delete requests[reqId];

  // There was no matching saved request, this is an error
  if (!query) {
    return res.render('error', { error: 'No matching authorization request' });
  }

  // User did not grant access to the client for the provided scope
  if (!req.body.approve) {
    const url = formatResponseUrl(query.redirect_uri, { error: 'access_denied' });
    return res.redirect(url);
  }

  // User did give the permission to the client
  if (query.response_type === 'code') {
    const code = randomString.generate(8);
    const user = req.body.user;
    const scope = Object.keys(req.body)
      .filter(key => /^scope_/.test(key)) // find scopes
      .map(key => key.slice('scope_'.length)); // remove scope_ from the start of the string
    const client = getClient(query.client_id);
    const clientScope = client.scope ? client.scope.split(' ') : undefined;

    // client asked for a scope it couldn't have
    if (_.difference(clientScope, scope).length > 0) {
      const responseUrl = formatResponseUrl(query.redirect_uri, { error: 'invalid_scope' });
      return res.redirect(responseUrl);
    }
    
    // Save the code and request for later
    addCode(code, { authorizationEndPointRequest: query, scope, user });

    return res.redirect(formatResponseUrl(query.redirect_uri, {
      code,
      state: query.state
    }));
  }

  else if (query.response_type === 'token') {

    const scope = Object.keys(req.body)
      .filter(param => /^scope_/.test(param))
      .map(param => param.slice('scope_'.length));
    const client = getClient(query.client_id);
    const clientScope = client.scope ? client.scope.split(' ') : undefined;

    // Client asked for a scope it couldn't have
    if (_.difference(client, clientScope).length > 0) {
      return res.redirect(formatResponseUrl(query.redirect_uri, {
        error: 'invalid_scope'
      }));
    }

    const user = users[req.body.user];
    if (!user) {
      console.log(`Unknown user ${req.body.user}`);
      return res.status(500).render('error', {
        error: `Unknown user ${req.body.user}`
      });
    }

    console.log(`User ${user}`);

    const tokenResponse = generateTokens(req, res, query.client_id, user, clientScope);
    if (query.state) {
      tokenResponse.state = query.state;
    }
    const responseUrl = formatResponseUrl(req.redirect_uri, {}, qs.stringify(tokenResponse));

    return res.redirect(responseUrl);
  }

  else {
    // We got a response type we don't understand
    const responseUrl = formatResponseUrl(query.redirect_uri, { error: 'unsupported_response_type' });
    return res.redirect(responseUrl);
  }
};

exports.getToken = function getToken(req, res, next) {

  let clientId, clientSecret;
  const auth = req.headers['authorization'];
  if (auth) {
    // Check the auth header
    [clientId, clientSecret] = new Buffer(auth.slice('basic '.length), 'base64')
      .toString()
      .split(':');
  }

  // Otherwise check the post body
  if (req.body.client_id) {
    // If we've already seen the client's credentials in the authorization header, this is an error
    if (clientId) {
      console.log('Client attempted to authenticate with multiple methods');
      return res.status(401).json({ error: 'invalid_client' });
    }

    clientId = req.body.client_id;
    clientSecret = req.body.client_secret;
  }

  const client = getClient(clientId);
  if (!client) {
    console.log(`Unknown client ${clientId}`);
    return res.status(401).json({ error: 'invalid_client' });
  }

  if (client.client_secret !== clientSecret) {
    console.log(`Mismatched client secret, expected ${client.client_secret} but got ${clientSecret}`);
    return res.status(401).json({ error: 'invalid_client' });
  }

  if (req.body.grant_type === 'authorization_code') {
    const code = codes[req.body.code];

    // Could not found the corresponding code
    if (!code) {
      console.log(`Unknown code ${req.body.code}`);
      return res.status(400).json({ error: 'invalid_grant' });
    }

    // Burn our code, it's been used;
    delete codes[req.body.code];

    // Client mismatch error
    if (code.authorizationEndPointRequest.client_id !== clientId) {
      console.log(`Client mismatch, expected ${code.authorizationEndPointRequest.client_id} but got ${clientId}`);
      return res.status(400).json({ error: 'invalid_grant' });
    }

    const user = users[code.user];
    if (!user) {
      console.log(`Unknown user ${code.user}`);
      return res.status(500).render('error', {
        error: `Unknown user ${code.user}`
      });
    }

    console.log(`User ${user}`);
    const tokenResponse = generateTokens(req, res, clientId, user, code.scope, code.authorizationEndPointRequest.nonce, true);

    console.log(`Issued tokens for code ${req.body.code}`);
    return res.status(200).json(tokenResponse);
  }

  else if (req.body.grant_type === 'client_credentials') {
    const scope = req.body.scope ? req.body.scope.split(' ') : undefined;
    const clientScope = client.scope ? client.scope.split(' ') : undefined;

    // Client asked for a scope it couldn't have
    if (_.difference(scope, clientScope).length > 0) {
      return res.status(400).json({error: 'invalid_scope'});
    }

    const accessToken = randomString.generate();
    const tokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      scope: scope.join(' ')
    };

    dbPromise.then(db => db.collection('access_tokens')
      .insertOne({
        access_token: accessToken,
        client_id: clientId,
        scope
      }))
      .then(result => console.log(`Issuing access token ${accessToken}`));
    
    return res.status(200).json(tokenResponse);
  }

  else if (req.body.grant_type === 'refresh_token') {

  }

  else if (req.body.grant_type === 'password') {

  }
};

function generateTokens(req, res, clientId, user, scope, nonce, generateRefreshToken) {
  const access_token = randomString.generate();
  let refresh_token = null;

  if (generateRefreshToken) {
    refresh_token = randomString.generate();
  }

  dbPromise.then(db => db.collection('access_tokens')
    .insertOne({
      access_token,
      scope,
      client_id: clientId,
      user: user.preferred_username
  }))
  .then(result => console.log('inserted access token', result))
  .catch(console.error.bind(console));

  if (refresh_token) {
    dbPromise.then(db => db.collection('refresh_tokens')
      .insertOne({
        refresh_token,
        scope,
        client_id: clientId,
        user: user.preferred_username
      }))
      .then(result => console.log('inserted refresh token', result))
      .catch(console.error.bind(console));
  }

  return {
    access_token,
    refresh_token,
    token_type: 'Bearer',
    scope
  };
}

function formatResponseUrl(url, query, hash) {
  const parsedUrl = url.parse(url);
  delete parsedUrl.search;
  parsedUrl.query = Object.assign({}, parsedUrl.query || {}, query);
  hash ? parsedUrl.hash = hash : '';
  return url.format(parsedUrl);
}