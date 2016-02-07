var restful = require('node-restful'),
mongoose = restful.mongoose;

module.exports = restful.model('user', mongoose.Schema({
  name: String,
  password: String,
}));
