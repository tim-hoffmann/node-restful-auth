var express = require('express'),
bodyParser = require('body-parser'),
methodOverride = require('method-override'),
morgan = require('morgan'),
restful = require('node-restful'),
mongoose = restful.mongoose;
var app = express();

var config = require('./config');

var user = require('./app/route/users');

app.use(morgan('dev'));
app.use(bodyParser.urlencoded({'extended':'true'}));
app.use(bodyParser.json());
app.use(bodyParser.json({type:'application/vnd.api+json'}));
app.use(methodOverride());
app.set('secret', config.secret);

mongoose.connect(config.database);

app.user = user;

user.register(app, '/users');

app.listen(3000);
console.log('Server is listening on 3000');
