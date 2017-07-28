const express = require('express');
const bodyParser = require('body-parser');
const nosql = require('nosql').load('database.nosql');
const _ = require('lodash');
const cors = require('cors');
const {join} = require('path');

const app = express();

app.use(bodyParser.urlencoded({extended: true}));
app.set('view engine', 'pug');
app.set('views', join(__dirname, 'files', 'protected-resource'));
app.set('json spaces', 4);

app.use('/', express.static(join(__dirname, 'files', 'protected-resource')));
app.use(cors());

const resource = {
  name: 'Protected Resource',
  description: 'This data has been protected by OAuth 2.0'
};

const getAccessToken = (req, res, next) => {
  let inToken = null;
  const auth = req.headers['authorization'];

  // The client has provided the bearer authorization header
  if (auth && auth.toLowerCase().indexOf('bearer') === 0) {
    inToken = auth.slice('bearer '.length);
  }
  else if (req.body && req.body.access_token) {
    inToken = req.body.access_token;
  }
  else if (req.query && req.query.access_token) {
    inToken = req.body.access_token;
  }

  console.log(`Incoming Token: ${inToken}`);
  nosql.one(
    token => { if (token.access_token === inToken) return token; },
    (err, token) => {
      if (token) console.log('We found a matching token: ${inToken}');
      else console.log('No matching token was found');

      req.access_token = token;
      return next();
    }
  )
};

const requireAccessToken = (req, res, next) =>
  typeof req.access_token !== 'undefined' ? next() : res.status(401).end();

const aliceFavorites = {
  movies: ['The Multidimensional Vector', 'Space Fights', 'Jewelry Boss'],
  foods: ['bacon', 'pizza', 'bacon pizza'],
  music: ['techno', 'industrial', 'alternative']
};

const bobFavorites = {
  movies: ['An Unrequited Love', 'Several Shades of Turquoise', 'Think of The Children'],
  foods: ['bacon', 'kale', 'gravel'],
  music: ['baroque', 'ukulele', 'baroque ukulele']
};

app.get('/favorites',
  getAccessToken,
  requireAccessToken,
  (req, res, next) => {
    // Get different user information based on the information of who approved the token
    const unknown = {user: 'Unknown', favorites: {movies: [], music: [], foods: []}};
    res.json(unknown);
  });

const server = app.listen(9002, 'localhost', () => {
  const host = server.address().address;
  const port = server.address().port;
  console.log(`OAuth protected resource server is listening at http://${host}:${port}`);
});
