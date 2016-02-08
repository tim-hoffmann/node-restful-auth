var bcrypt = require('bcryptjs'),
jwt = require('jsonwebtoken');
var userModel = require('../models/user');
var config = require('../../config');

userModel.methods(['get', 'post', 'put', 'delete']);

// GET
userModel.before('get', authenticateToken);
userModel.before('get', function(req, res, next) {
  userModel.findOne({
    _id: req.decoded._doc._id
  },
  function(err, user) {
    if (err) throw err;

    return res.json(user);
  });
});

// POST
userModel.before('post', hashPassword);
userModel.before('post', function(req, res, next) {
  userModel.findOne({
    name: req.body.name
  },
  function(err, user) {
    if (err) throw err;

    if(user) {
      return res.json({success: false, message: 'Username already exists.'});
    }

    next();
  });
});

// PUT
userModel.before('put', authenticateToken);
userModel.before('put', hashPassword);

// DELETE
userModel.before('delete', authenticateToken);
userModel.before('delete', authorize);

// Route for User Authentication
userModel.route('authenticate.post', function(req, res, next) {
  userModel.findOne({
    name: req.body.name
  },
  '+password',
  function(err, user) {
    if (err) throw err;

    if (user && comparePasswordHash(req.body.password, user.password)) {
      // create a token
      var token = jwt.sign(user, config.secret, {
        expiresInMinutes: 1440 // expires in 24 hours
      });
      res.json({
        success: true,
        token: token
      });
    }
    else {
      res.json({
        success: false,
        message: 'Authentication failed.' });
    }
  });
});

// Token Authentication
function authenticateToken(req, res, next) {
  // check header or url parameters or post parameters for token
  var token = req.body.token || req.query.token || req.headers['x-access-token'];

  // decode token
  if (token) {
    // verifies secret and checks exp
    jwt.verify(token, config.secret, function(err, decoded) {
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

// Check permission for User Object
function authorize(req, res, next) {
  var requestedId = req.body._id || req.params.id;

  if(requestedId != req.decoded._doc._id) {
    return res.json({success: false, message: 'No Authorization.'});
  }

  next();
}

// Password hashing
function hashPassword(req, res, next) {
  if(!req.body.password) next();

  bcrypt.hash(req.body.password, 10, function(err, hash) {
    if (err) throw err;

    req.body.password = hash;

    next();
  });
}

// Comparing Password Hash
function comparePasswordHash(password, passwordHash) {
  return bcrypt.compareSync(password, passwordHash);
}

module.exports = userModel;
