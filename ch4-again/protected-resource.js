const express = require('express');
const bodyParser = require('body-parser');
const _ = require('lodash');
const cors = require('cors');
const { join } = require('path');
const dbPromise = require('./db');

const app = express();

// support form-encoded bodies (for bearer tokens)
app.use(bodyParser.urlencoded({ extended: true }));

app.set('view engine', 'pug');
app.set('views', join(__dirname, 'file', 'protected-resource'));
app.set('json spaces', 4);

app.use('/', express.static(join(__dirname, 'file', 'protected-resource')));
app.use(cors());

const resource = {
  name: 'Protected Resource',
  description: 'This data has been protected by OAuth 2.0'
};

const getAccessToken = function getAccessToken(req, res, next) {
  let inToken = null;
  let auth = req.headers['authorization'];
  
  if (auth && auth.toLowerCase().indexOf('bearer') === 0) {
    inToken = auth.slice('bearer '.length);
  }
  else if (req.body && req.body.access_token) {
    inToken = req.body.access_token;
  }
  else if (req.query && req.query.access_token) {
    inToken = req.query.access_token;
  }
  
  console.log(`Incoming token ${inToken}`);
  // @TODO: db query logic for accepted tokens
  
};

const requireAccessToken = function requireAccessToken(req, res, next) {
  if (req.access_token) {
    return next();
  }
  return res.status(401).end(); // should i not send a json error message instead?
};

const aliceFavorites = {
  movies: ['The Multidimensional Vector', 'Space Flights', 'Jewelry Boss'],
  foods: ['bacon', 'pizza', 'bacon pizza'],
  music: ['techno', 'industrial', 'alternative']
};

const bobFavorites = {
  movies: ['An Unrequited Love', 'Several Shades of Turquoise', 'Think Of The Children'],
  foods: ['bacon', 'kale', 'gravel'],
  music: ['baroque', 'ukulele', 'baroque ukulele']
};

app.get('/favorites',
  getAccessToken, // retrieve access token
  requireAccessToken, // validate access token
  (req, res, next) => {
    if (req.access_token.user === 'alice') {
      return res.json({ user: 'Alice', favorites: aliceFavorites });
    }
    else if (req.access_token.user === 'bob') {
      return res.json({ user: 'Bob', favorites: bobFavorites });
    }
    else {
      return res.json({ user: 'Unknown', favorites: { movies: [], foods: [], music: [] } });
    }
  });

const server = app.listen(9002, 'localhost', () => {
  const host = server.address().address;
  const port = server.address().port;
  console.log(`OAuth Resource Server is listening at http://${host}:${port}`);
});

module.exports = server;