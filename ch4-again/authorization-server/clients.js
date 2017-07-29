'use strict';

// clients info
const clients = [
  {
    client_id: 'oauth-client-1',
    client_secret: 'oauth-client-secret-1',
    redirect_uris: ['http://localhost:9000/callback'],
    scope: 'movies foods music'
  }
];

const getClient = function getClient(clientId) {
  return clients.find(client => client.client_id === clientId);
};

exports.clients = clients;
exports.getClient = getClient;
