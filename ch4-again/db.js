const MongoClient = require('mongodb').MongoClient;
const url = 'mongodb://localhost:27017/oauth2';

module.exports = MongoClient.connect(url);