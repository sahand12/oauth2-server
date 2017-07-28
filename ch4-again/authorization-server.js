const express = require('express');
const url = require('url');
const bodyParser = require('body-parser');
const randomString = require('randomstring');
const dbPromise = require('./db');
const queryString = require('querystring');
const { join } = require('path');
const _ = require('lodash');
_.string = require('underscore.string');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.set('view engine', 'pug');
app.set('views', join(__dirname, 'files', 'authorization-server'));
app.set('json spaces', 4);

// authorization server information
const authServerInfo = {
  authorizationEndPoint: 'http://localhost:9001/authorize',
  tokenEndPoint: 'http://localhost:9001/token'
};

// clients info
const clients = [
  {
    client_id: 'oauht-client-1',
    client_secret: 'oauth-client-secret-1',
    redirect_uris: ['http://localhost:9000/callback'],
    scope: 'movies foods music'
  }
];

const users = {
  'alice': {
    "sub": "9XE3-JI34-00132A",
		"preferred_username": "alice",
		"name": "Alice",
		"email": "alice.wonderland@example.com",
		"email_verified": true
	},
	
	"bob": {
		"sub": "1ZT5-OE63-57383B",
		"preferred_username": "bob",
		"name": "Bob",
		"email": "bob.loblob@example.net",
		"email_verified": false
	},

	"carol": {
		"sub": "F5Q1-L6LGG-959FS",
		"preferred_username": "carol",
		"name": "Carol",
		"email": "carol.lewis@example.net",
		"email_verified": true,
		"username" : "clewis",
		"password" : "user password!"
 	}
};

const codes = {};
const requests = {};

const getClient = clientId => clients.find(client => client.client_id === clientId);
const getUser = username => Object.entries(users).filter(([key, val]) => val.username === username)[0];