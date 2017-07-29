const express = require('express');
const bodyParser = require('body-parser');
const { join } = require('path');

const { indexRoute, authorize, approve, getToken } = './routes';

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.set('view engine', 'pug');
app.set('views', join(__dirname, 'files', 'authorization-server'));
app.set('json spaces', 4);

// Routes
app.get('/', indexRoute);
app.get('/authorize', authorize);
app.post('/approve', approve);
app.post('/token', getToken);
app.use('/', express.static(join(__dirname, 'file', 'authorization-server')));

const server = app.listen(9001, 'localhost', () => {
  const host = server.address().address;
  const port = server.address().port;
  console.log(`OAuth Authorization Server is listening at http://${host}:${port}`);
});
