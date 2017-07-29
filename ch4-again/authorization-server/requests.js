'use strict';

const requests = {};

const addRequest = function addRequest(id, request) {
  requests[id] = request;
};

exports.requests = requests;
exports.addRequest = addRequest;