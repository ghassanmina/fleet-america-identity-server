'use strict';
var jwt = require('jsonwebtoken');
var randtoken = require('rand-token');
var config = require('../../config');
var bcrypt = require('bcryptjs');
var mongoose = require('mongoose'),
    Application = mongoose.model('Application'),
    User = mongoose.model('Users');
var crypto = require('crypto');

function decrypt_token(application_id, token) {
    var algorithm = config.crypto_algorithm;
    var password = application_id;

    var decipher = crypto.createDecipher(algorithm, password);
    var decrypted_token = decipher.update(token, 'hex', 'utf8');
    decrypted_token += decipher.final('utf8');
    return JSON.stringify(eval('(' + decrypted_token + ')'));
}

function get_logged_user(loggeduser, callback) {
    User.findOne({
            UserName: loggeduser
        }, {
            _id: 0,
            UserName: 1,
            EmailConfirmed: 1,
            LockedOut: 1
        },
        function(err, userinfo) {
            if (err) {
                callback(err, null);
            } else {
                callback(null, userinfo);
            }
        });
}

exports.list_all_users = function(req, res) {
    //http://localhost:3000/getusers
    //token:eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.
    //app:TeenShield

    Application.findOne({
        ApplicationName: req.body.app
    }, function(err, application) {
        if (err) {
            res.send(err);
        } else {
            try {
                var decoded = jwt.verify(req.body.token, application._id);
                var token_data = JSON.parse(decrypt_token(application._id, decoded.data));

                get_logged_user(token_data.user, function(err, userinfo) {
                    if (err) {
                        res.send(err);
                    }
                    if (!userinfo.EmailConfirmed) {
                        res.json('Unactivated user');
                    } else {
                        if (userinfo.LockedOut) {
                            res.json('Locked out user');
                        } else {
                            User.find({}, {
                                    _id: 0,
                                    FirstName: 1,
                                    LastName: 1,
                                    UserName: 1,
                                    MobilePhone: 1,
                                    Email: 1,
                                    RecoveryEmail: 1,
                                    Phone: 1,
                                    EmailConfirmed: 1,
                                    Roles: 1,
                                    LockedOut: 1,
                                    LastLoginDate: 1,
                                    LastPasswordChangeDate: 1,
                                    LastLockedOutDate: 1,
                                    FailedPasswordAttemptCount: 1,
                                    FailedPasswordAttemptStart: 1
                                },
                                function(err, user) {
                                    if (err) {
                                        res.send(err);
                                    } else {
                                        res.json(user);
                                    }
                                });
                        }
                    }
                });

            } catch (e) {
                res.send(e);
            }
        }
    });
};

exports.read_a_user = function(req, res) {
    //http://localhost:3000/getuser
    //UserName:ghassan.mina@gmail.com
    //app:TeenShield
    //token:eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.

    Application.findOne({
        ApplicationName: req.body.app
    }, function(err, application) {
        if (err) {
            res.send(err);
        } else {
            try {
                var decoded = jwt.verify(req.body.token, application._id);
                var token_data = JSON.parse(decrypt_token(application._id, decoded.data));

                get_logged_user(token_data.user, function(err, userinfo) {
                    if (err) {
                        res.send(err);
                    }
                    if (!userinfo.EmailConfirmed) {
                        res.json('Unactivated user');
                    } else {
                        if (userinfo.LockedOut) {
                            res.json('Locked out user');
                        } else {
                            User.findOne({
                                    UserName: req.body.UserName
                                }, {
                                    _id: 0,
                                    FirstName: 1,
                                    LastName: 1,
                                    UserName: 1,
                                    MobilePhone: 1,
                                    Email: 1,
                                    RecoveryEmail: 1,
                                    Phone: 1,
                                    EmailConfirmed: 1,
                                    Roles: 1,
                                    LockedOut: 1,
                                    LastLoginDate: 1,
                                    LastPasswordChangeDate: 1,
                                    LastLockedOutDate: 1,
                                    FailedPasswordAttemptCount: 1,
                                    FailedPasswordAttemptStart: 1
                                },
                                function(err, user) {
                                    if (err) {
                                        res.send(err);
                                    } else {
                                        res.json(user);
                                    }
                                });
                        }
                    }
                });


            } catch (e) {
                res.send(e);
            }
        }
    });
};

//TODO: Create user page
exports.create_a_user = function(req, res) {

    //http://localhost:3000/createuser
    //{"ApplicationId" : "58dfc709f5014867a384738a",
    //"FirstName" : "Ghassan", "LastName" : "Mina", "UserName" : "ghassanmina1@gmail.com",
    //Password" : "10072004", "Salt" : "$2a$10$p1c8IntB.bSXMeClqcCwbO", "MobilePhone" : "416-566-3179",
    //"Email" : "ghassanmina1@gmail.com", "RecoveryEmail" : ["ghassanmina1@gmail.com", "ghassanmina1@yahoo.com"],
    //"Phone" : "289-342-0121",
    //"Roles" : [ { "RoleName" : "admin", "Description" : "Admin role" }, {"RoleName" : "test", "Description" : "Test role" }]}

    Application.findOne({
            ApplicationName: req.body.Application
          },
        function(err, application) {
            if (err) {
                res.send(err);
              } else {
              var bcrypt = require('bcryptjs');
              var salt = bcrypt.genSaltSync(10);
              var hash = bcrypt.hashSync(req.body.Password, salt);
              var jsonuser = {
                  Application: application._id, //req.body.ApplicationId,
                  FirstName: req.body.FirstName,
                  LastName: req.body.LastName,
                  UserName: req.body.UserName,
                  Password: hash,
                  Salt: salt,
                  MobilePhone: req.body.MobilePhone,
                  Email: req.body.Email,
                  RecoveryEmail: req.body.RecoveryEmail,
                  Phone: req.body.Phone,
                  Roles: req.body.Roles,
                  EmailConfirmed: false,
                  LockedOut: false,
                  Created_date: new Date(),
                  LastLoginDate: new Date('1970-01-01'),
                  LastPasswordChangeDate: new Date('1970-01-01'),
                  LastLockedOutDate: new Date('1970-01-01'),
                  FailedPasswordAttemptCount: 0,
                  FailedPasswordAttemptStart: new Date('1970-01-01'),
                  RefreshToken: '',
                  Reset_Pin: 0,
                  Reset_Pin_Date: new Date('1970-01-01'),
                  Reset_Page_Token: ''
              }

              var new_user = new User(jsonuser);
              new_user.save(function(err, user) {
                  if (err) {
                      res.json({
                          status: 'failed',
                          user_name: req.body.UserName,
                          error: err
                      });
                  } else {
                      res.json({
                          status: 'success',
                          user_name: req.body.UserName,
                          error: ''
                      });
                  }
              });
            }
          });
};

exports.authenticate_a_user = function(req, res) {
    //http://localhost:3000/authenticate
    //UserName:ghassan.mina@gmail.com
    //Password:10072004
    //Application:TeenShield

    User.find({
        UserName: req.body.UserName
    }, function(err, user) {
        if (err) {
            res.send(err);
        } else {
            if(user.length>0){
              var salt = user[0].Salt;
              if (!user[0].LockedOut) {
                  Application.find({
                      ApplicationName: req.body.Application
                  }, function(err, application) {
                      if (err) {
                          res.send(err);
                      } else {
                          var tokeninfo = "{user: '" + req.body.UserName + "', roles: [" + user[0].Roles + "]}";
                          //Encrypt The data
                          var algorithm = config.crypto_algorithm,
                          password = application[0]._id;
                          var ciphertoken = crypto.createCipher(algorithm, password);
                          var cryptedtokendata = ciphertoken.update(tokeninfo, 'utf8', 'hex');
                          cryptedtokendata += ciphertoken.final('hex');

                          var token = jwt.sign({
                              data: cryptedtokendata
                          }, application[0]._id, {
                              expiresIn: 60 * 60,
                              issuer: config.name,
                              algorithm: config.jwt_algorithm
                          });

                          var refreshtoken = crypto.createCipher(algorithm, password);
                          var cryptedrefreshtoken = refreshtoken.update(randtoken.uid(256), 'utf8', 'hex');
                          cryptedrefreshtoken += refreshtoken.final('hex');
                          var refreshToken = jwt.sign({
                              refreshtoken: cryptedrefreshtoken,
                              token: token
                          }, application[0]._id, {
                              expiresIn: ((60 * 60) * 24) * 7,
                              issuer: config.name,
                              algorithm: config.jwt_algorithm
                          });
                          user[0].RefreshToken = refreshToken;
                          user[0].save(function(err, updatetoken) {
                              if (err) res.send(err);
                              var isAuthenticated = bcrypt.compareSync(req.body.Password, user[0].Password);
                              console.log(isAuthenticated);
                              res.json({
                                  Authenticated: isAuthenticated,
                                  Token: isAuthenticated == true ? token : "",
                                  RefreshToken: isAuthenticated == true ? refreshToken : ""
                              });
                          });
                      }
                  });
              } else {
                  res.json({
                      Authenticated: false,
                      Token: '',
                      RefreshToken: ''
                  });
              }
            } else {
              res.json({
                  Authenticated: false,
                  Token: '',
                  RefreshToken: ''
              });
            }
        }
    });
};

exports.refresh_token = function(req, res) {
    Application.find({
            ApplicationName: req.body.Application
        },
        function(err, application) {
            if (err) {
                res.send(err);
            } else {
                jwt.verify(req.body.RefreshToken, application[0]._id,
                    function(err, decoded) {
                        if (err) {
                            res.send(err);
                        } else {
                            User.find({
                                UserName: req.body.UserName
                            }, function(err, user) {
                                if (err) {
                                    res.send(err);
                                } else {
                                    if (user[0].RefreshToken == req.body.RefreshToken) {
                                        var tokeninfo = "user: " + req.body.UserName + ", roles: " + user[0].Roles;
                                        var algorithm = config.crypto_algorithm,
                                            password = application[0]._id;
                                        var ciphertoken = crypto.createCipher(algorithm, password);
                                        var cryptedtokendata = ciphertoken.update(tokeninfo, 'utf8', 'hex');
                                        cryptedtokendata += ciphertoken.final('hex');
                                        var token = jwt.sign({
                                            data: cryptedtokendata
                                        }, application[0]._id, {
                                            expiresIn: 60 * 60,
                                            issuer: config.name,
                                            algorithm: config.jwt_algorithm
                                        });
                                        res.json({
                                            refreshtokenstatus: "valid",
                                            token: token
                                        });
                                    } else {
                                        res.json({
                                            refreshtokenstatus: "invalid",
                                            token: ""
                                        });
                                    }
                                }
                            });
                        }
                    });
            }
        });
};

exports.reset_password = function(req, res) {
  var algorithm = config.crypto_algorithm;
  var password = req.body.Application;

  var decipher = crypto.createDecipher(algorithm, config.crypt_pwd);
  var decrypted_user = decipher.update(req.body.UserName, 'hex', 'utf8');
  decrypted_user += decipher.final('utf8');

  User.findOne({
        UserName: decrypted_user
    }, function(err, user) {
        if (err) {
            res.send(err);
        } else {
          if(user!=null){
            if (req.body.Application == user.Application) {
                if (user.LockedOut == false) {
                  var blnReset = true;
                  if(user.Reset_Pin!=0){
                    var d1 = new Date(user.Reset_Pin_Date);
                    var d2 = new Date();

                    var diff = ((d2-d1) / 3600000).toFixed(0);
                    console.log(diff);
                    if(diff < parseInt(config.reset_pin_age))
                    {
                        console.log('user pin age');
                        if(user.Reset_Pin!=req.body.Reset_Pin)
                          {
                            blnReset = false;
                          }
                    }
                    else {
                        blnReset = false;
                    }
                  }
                  else{
                    blnReset = false;
                  }

                  if(blnReset==true)
                  {
                    if(req.body.Password.length> 0)
                    {
                      var salt = bcrypt.genSaltSync(10);
                      var hash = bcrypt.hashSync(req.body.Password, salt);
                      user.Password = hash;
                      user.Salt = salt;
                      user.LastPasswordChangeDate = new Date();
                      if (user.FailedPasswordAttemptCount > 0) {
                        user.FailedPasswordAttemptCount = 0;
                      }
                      user.save(function(err, updateuser) {
                        if (err) {
                          res.send(err);
                        } else {
                          console.log(blnReset);
                          console.log(user.Reset_Pin);
                          console.log(req.body.Reset_Pin);
                          res.json({
                            PasswordChanged: true,
                            Description: 'Password changed successfully'
                          });
                        }
                      });
                    } else {
                      res.json({
                        PasswordChanged: false,
                        Description: 'Password can\'t be blank'
                      });
                    }
                  }
                  else {
                    res.json({
                        PasswordChanged: false,
                        Description: 'No valid password reset request was sent.'
                    });
                  }
                }
                else {
                    res.json({
                        PasswordChanged: false,
                        Description: 'User name is locked out. Contact the system administrator to unlock it.'
                    });
                }
            } else {
                res.json({
                    PasswordChanged: false,
                    Description: 'User name is unavailable.'
                });
            }
          }
          else {
            res.json({
              PasswordChanged: false,
              Description: 'User name is unavailable.'
            });
          }
        }
    });
};

//TODO: Reset password page
//TODO: to remove recovery email with click here shortcut in the email
exports.reset_password_request = function(req, res) {
    User.findOne({
            UserName: req.body.UserName
        },
        function(err, user) {
            //Send email to recover
            var nodemailer = require('nodemailer');
            var transporter = nodemailer.createTransport({
                name: config.email_server_name,
                host: config.email_host,
                port: config.smtp_port,
                secure: true, // use SSL
                auth: {
                    user: config.email_username,
                    pass: config.email_password
                }
            });

            var username = req.body.UserName.substring(0, 2);
            var user_name = '';
            if (config.username_is_email) {
                username = username + '*****@' + req.body.UserName.split('@')[1];
            } else {
                username = username + '*****'
            }

            var rando_code = Math.floor(Math.random() * (9999999 - 1000000) + 1000000);
            var reset_page_token = randtoken.uid(256)
            user.Reset_Pin = rando_code;
            user.Reset_Pin_Date = new Date();
            user.Reset_Page_Token = reset_page_token;
            user.save(
                function(err, updateuser) {
                    if (err) {
                        res.json({
                            Success: false,
                            RecoveryEmail: user.RecoveryEmail,
                            Description: 'Failed to save the recovery pin code in the database ' + err
                        });
                    } else {
                        // setup email data with unicode symbols
                        let mailOptions = {
                            from: config.email_from, // sender address
                            to: user.RecoveryEmail, // list of receivers
                            subject: config.email_reset_subject, // Subject line
                            html: '<h3><span style="color: #999999;">' + config.company_name + ' account</span></h3>' +
                                '<h1><span style="color: #3366ff;">Password reset code</span></h1>' +
                                '<p>Please use this code to reset the password for the ' + config.company_name + ' account ' +
                                '<a href="mailto:' + username + '" target="_blank" rel="nofollow">' + username + '</a>.</p>' +
                                '<p>Here is your code: <strong>' + rando_code + '</strong></p>' +
                                '<p>If you don\'t recognize the ' + config.company_name + ' account ' +
                                '<a href="mailto:' + username + '" target="_blank" rel="nofollow">' + username + '</a>, ' +
                                'you can <a href="' + config.password_reset_page + '?rpt=' + reset_page_token +
                                '" target="_blank">click here</a> ' +
                                'to remove your email address from that account.</p>' +
                                '<p>&nbsp;</p><p>Thanks,<br />' + config.company_name + ' account team</p>'
                        };
                        // send mail with defined transport object
                        transporter.sendMail(mailOptions, (error, info) => {
                            if (error) {
                                res.json({
                                    Success: false,
                                    RecoveryEmail: user.RecoveryEmail,
                                    Description: 'The API failed to send by email the recovery code ' + error
                                });
                            } else {
                                console.log('Message %s sent: %s', info.messageId, info.response);
                                res.json({
                                    Success: true,
                                    RecoveryEmail: user.RecoveryEmail,
                                    Description: 'Email is sent with the recovery code to ' + user.RecoveryEmail
                                });
                            }
                        });
                    }
                });
        });
};

exports.update_a_user = function(req, res) {
    //http://localhost:3000/updateuser
    //{"token" :"eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJkYXRhI",
    //"app" : "TeenShield", "FirstName" : "Ghassan", "LastName" : "Mina",
    //"UserName" : "ghassanmina1@gmail.com", "MobilePhone" : "416-566-3179", "Email" : "ghassanmina1@gmail.com",
    //"RecoveryEmail" : ["ghassanmina1@gmail.com", "ghassanmina1@yahoo.com"],
    //"Phone" : "289-342-0121", "Roles" : [{ "RoleName" : "admin", "Description" : "Admin role"},
    //{"RoleName" : "test", "Description" : "Test role" }]}

    Application.findOne({
        ApplicationName: req.body.app
    }, function(err, application) {
        if (err) {
            res.send(err);
        } else {
            try {
                var decoded = jwt.verify(req.body.token, application._id);
                var token_data = JSON.parse(decrypt_token(application._id, decoded.data));

                get_logged_user(token_data.user, function(err, userinfo) {
                    if (err) {
                        res.send(err);
                    } else {
                        if (!userinfo.EmailConfirmed) {
                            res.json('Unactivated user');
                        } else {
                            if (userinfo.LockedOut) {
                                res.json('Locked out user');
                            } else {

                                User.findOne({
                                    UserName: req.body.UserName
                                }, {}, function(err, user) {
                                    if (err) {
                                        res.send(err);
                                    } else {
                                        user.FirstName = req.body.FirstName;
                                        user.LastName = req.body.LastName;
                                        user.MobilePhone = req.body.MobilePhone;
                                        user.Email = req.body.Email;
                                        user.RecoveryEmail = req.body.RecoveryEmail;
                                        user.Phone = req.body.Phone;
                                        user.Roles = req.body.Roles;
                                        user.save(function(err, user) {
                                            if (err) {
                                                res.json({
                                                    status: 'failed',
                                                    user_name: req.body.UserName,
                                                    error: err
                                                });
                                            } else {
                                                res.json({
                                                    status: 'success',
                                                    user_name: req.body.UserName,
                                                    error: ''
                                                });
                                            }
                                        });
                                    }
                                });
                            }
                        }
                    }
                });
            } catch (e) {
                res.send(e);
            }
        }
    });
};

exports.delete_a_user = function(req, res) {
  //http://localhost:3000/removeuser
  //app:TeenShield
  //token:eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.
  //UserName:ghassanmina1@gmail.com

  Application.findOne({
      ApplicationName: req.body.app
  }, function(err, application) {
      if (err) {
          res.send(err);
      } else {
          try {
            var decoded = jwt.verify(req.body.token, application._id);
            var token_data = JSON.parse(decrypt_token(application._id, decoded.data));

            get_logged_user(token_data.user, function(err, userinfo) {
                if (err) {
                    res.send(err);
                } else {
                    if (!userinfo.EmailConfirmed) {
                        res.json('Unactivated user');
                    } else {
                        if (userinfo.LockedOut) {
                            res.json('Locked out user');
                        } else {
                          User.remove({
                              UserName: req.body.UserName
                          }, function(err, user) {
                              if (err) {
                                  res.send(err);
                                }
                                else {


                                  get_logged_user(token_data.user, function(err, userinfo) {
                                      if (err) {
                                          res.send(err);
                                      } else {
                                          if (!userinfo.EmailConfirmed) {
                                              res.json('Unactivated user');
                                          } else {
                                              if (userinfo.LockedOut) {
                                                  res.json('Locked out user');
                                              } else {
                                                res.json({
                                                    status: 'success',
                                                    user_name: req.body.UserName,
                                                    error: ''
                                                });
                                              }
                                            }
                                          }
                                        });
                            }
                          });
                        }
                      }
                    }
                  }
                );
          }
          catch(e) {
            res.send(e);
          }
        }
      });
};

exports.read_app = function(req, res) {
  //http://localhost:3000/app
  //app:TeenShield
  //token:eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.
    Application.findOne({
        ApplicationName: req.body.app
    }, function(err, application) {
      if (err) {
          res.send(err);
      } else {
        try {
          var decoded = jwt.verify(req.body.token, application._id);
          var token_data = JSON.parse(decrypt_token(application._id, decoded.data));
          res.json(application);
        }
        catch(e) {
          res.send(e);
        }
      }
    });
};
