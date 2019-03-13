'use strict';
var mongoose = require('mongoose');
mongoose.Promise = global.Promise;

var Schema = mongoose.Schema;

var UsersSchema = new Schema({
  Application : { type: String, Required: 'Missing application' },
  FirstName: { type: String, Required: 'Missing first name' },
  LastName: { type: String, Required: 'Missing last name'},
  UserName : { type: String, Required: 'Missing user name'},
  Password: { type: String, Required: 'Missing password'},
  Salt: String,
  MobilePhone: { type: String, Required: 'Missing mobile phone number'},
  Email: { type: String, Required: 'Missing email' },
  RecoveryEmail: [{ type: String, Required: 'Missing recovery email' }],
  Phone: { type: String, Required: 'Missing phone number'},
  Roles: [{ RoleName: String, Description: String }],
  EmailConfirmed: Boolean,
  LockedOut: Boolean,
  Created_date: Date,
  LastLoginDate: Date,
  LastPasswordChangeDate: Date,
  LastLockedOutDate: Date,
  FailedPasswordAttemptCount: Number,
  FailedPasswordAttemptStart: Date,
  RefreshToken: String,
  Reset_Pin: Number,
  Reset_Pin_Date: Date,
  Reset_Page_Token: String
});

module.exports = mongoose.model('Users', UsersSchema);
