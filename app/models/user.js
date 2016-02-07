var restful = require('node-restful'),
mongoose = restful.mongoose;

module.exports = restful.model('user', mongoose.Schema({
  name: {type: String, required: true},
  password: {type: String, select: false}
}));
