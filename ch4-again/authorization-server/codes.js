'use strict';

const codes = {};

const addCode = function addRequest(id, request) {
  codes[id] = request;
};

exports.codes = codes;
exports.addRequest = addCode;