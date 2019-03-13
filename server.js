var config = require('./config');
var express = require('express'),
  app = express(),
  helmet = require('helmet'),
  port = process.env.PORT || config.binding_port,
  mongoose = require('mongoose'),
  User = require('./api/models/usersModel'),
  Application = require('./api/models/applicationModel'),
  bodyParser = require('body-parser');
var crypto = require('crypto');

app.use(helmet());

var os = require('os');
console.log('OS Type: ' + os.type());
console.log('Release: ' + os.release());
console.log('Platform: ' + os.platform());
console.log('');

//var bcrypt = require('bcryptjs');
//var salt = bcrypt.genSaltSync(10);
//var hash = bcrypt.hashSync("10072004", salt);
//console.log(bcrypt.compareSync("10072004", hash)); // true
//console.log(bcrypt.compareSync("not_bacon", hash)); // false


mongoose.Promise = global.Promise;
mongoose.connect(config.mongodb_connection);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
var routes = require('./api/routes/Routes');

routes(app);
app.use(function(req, res) {
  res.status(404).send({url: req.originalUrl + ' not found'})
  console.log('URL:' + req.originalUrl + ' not found');
});

app.listen(port);
console.log('Users RESTful API server started on: ' + port);
