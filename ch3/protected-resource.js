const express = require('express');
const bodyParser = require('body-parser');
const pug = require('pug');
const nosql = require('nosql').load('./database.nosql');
const cors = require('cors');
const {join} = require('path');

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

app.set('view engine', 'pug');
app.set('views', join(__dirname, 'files', 'protected-resource'));
app.set('json space', 4);

app.use('/', express.static(join(__dirname, 'files', 'protected-resource')));
app.use(cors());

const resource = {
  name: 'Protected Resource',
  description: 'This data has been protected by OAuth 2.0'
};

const getAccessToken = function getAccessToken (req, res, next) {
  // check the auth header first
  const auth = req.headers['authorization'];
  let inToken = null;

  if (auth && auth.toLowerCase().indexOf('bearer') === 0) {
    inToken = auth.slice('bearer '.length);
  } else if (req.body && req.body.access_token) {
    // not in the header, check in the form body
    inToken = req.body.access_token;
  } else if (req.query && req.query.access_token) {
    inToken = req.query.access_token;
  }

  console.log(`Incoming token: ${inToken}`);
  nosql.one(function (token) {
    if (token.access_token === inToken) {
      return token;
    }
  }, function (err, token) {
    if (token) {
      console.log(`We found a matching token: ${inToken}`);
    } else {
      console.log('No matching token was found.');
    }

    req.access_token = token;
    return next();
  });
};

app.options('/resource', cors());
app.post('/resource', cors(), getAccessToken, (req, res) =>
  req.access_token ? res.json(resource) : res.status(401).end()
);

const server = app.listen(9002, 'localhost', () => {
  const host = server.address().address;
  const port = server.address().port;

  console.log(`OAuth Resource Server is listening at http://${host}:${port}`);
});