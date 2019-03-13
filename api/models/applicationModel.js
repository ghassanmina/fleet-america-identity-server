'use strict';
var mongoose = require('mongoose');
mongoose.Promise = global.Promise;

var Schema = mongoose.Schema;

var ApplicationSchema = new Schema({
  _id: {
    type: String
  },
  ApplicationName: {
    type: String
  },
  Description: {
    type: String,
  },
  Created_date: {
    type: Date,
    default: Date.now
  }
});
module.exports = mongoose.model('Application', ApplicationSchema);
