var express = require('express'),
bodyParser = require('body-parser'),
methodOverride = require('method-override'),
morgan = require('morgan'),
restful = require('node-restful'),
mongoose = restful.mongoose;
var app = express();

var jwt    = require('jsonwebtoken'); // used to create, sign, and verify tokens
var config = require('./config'); // get our config file
var User   = require('./app/models/user'); // get our mongoose model

app.use(morgan('dev'));
app.use(bodyParser.urlencoded({'extended':'true'}));
app.use(bodyParser.json());
app.use(bodyParser.json({type:'application/vnd.api+json'}));
app.use(methodOverride());
app.set('secret', config.secret);

mongoose.connect(config.database);

app.user = User.methods(['get', 'post', 'put', 'delete']);

User.before('get', function(req, res, next){
  req.body.limit = 1;
  authenticate(req, res, next);
});

User.route('authenticate.post', function(req, res, next){
  User.findOne({
    name: req.body.name
  },
  function(err, user) {
    if (err) throw err;

    if (user || user.password === req.body.password) {
      // create a token
      var token = jwt.sign(user, app.get('secret'), {
        expiresInMinutes: 1440 // expires in 24 hours
      });
      res.json({
        success: true,
        token: token
      });
    } else {
      res.json({ success: false, message: 'Authentication failed.' });
    }
  })
});

function authenticate(req, res, next) {
  // check header or url parameters or post parameters for token
  var token = req.body.token || req.query.token || req.headers['x-access-token'];

  // decode token
  if (token) {
    // verifies secret and checks exp
    jwt.verify(token, app.get('secret'), function(err, decoded) {
      if (err) {
        return res.json({ success: false, message: 'Failed to authenticate token.' });
      }
      else {
        // if everything is good, save to request for use in other routes
        req.decoded = decoded;
        next();
      }
    });
  }
  else {
    // if there is no token
    // return an error
    return res.status(403).send({
      success: false,
      message: 'No token provided.'
    });
  }
}

User.register(app, '/users');

app.listen(3000);
console.log('Server is listening on 3000');
