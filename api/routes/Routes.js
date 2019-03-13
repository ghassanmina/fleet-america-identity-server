'use strict';
module.exports = function(app) {
  var users = require('../controllers/usersController');

  app.route('/createuser')
    .post(users.create_a_user);

  app.route('/updateuser')
    .post(users.update_a_user)

  app.route('/getusers')
    .post(users.list_all_users);

  app.route('/getuser')
    .post(users.read_a_user);

  app.route('/removeuser')
    .post(users.delete_a_user);

  app.route('/authenticate')
    .post(users.authenticate_a_user);

  app.route('/refreshtoken')
      .post(users.refresh_token);

  app.route('/app')
    .post(users.read_app);

  app.route('/passwordreset')
    .post(users.reset_password);

  app.route('/passwordresetrequest')
      .post(users.reset_password_request);
};
