var express = require('express');
var jwt = require('jwt-simple');
var bcrypt = require('bcrypt');

var app = express();
app.use(require('body-parser').json());

var User = require('./user');

var secretKey = 'supersecretkey';

//Get token after user validation
app.post('/session', function (req, res, next) {
  var username = req.body.username;

  User.findOne({username: username})
  .select('password')
  .exec(function (err, user) {
    if (err) { return next(err) }
    if (!user) { return res.sendStatus(401) }

    bcrypt.compare(req.body.password, user.password, function (err, valid) {

      if (err) { return next(err) }
      if (!valid) { return res.sendStatus(401) }

      var token = jwt.encode({username: username}, secretKey);
      res.json(token);
    })
  })
})

//Add a new user
app.post('/user', function(req, res, next) {
  var user = new User({username: req.body.username});
  bcrypt.hash(req.body.password, 10, function(err, hash) {
    user.password = hash;
    user.save(function (err, user) {
      if (err) { throw next(err)}
      res.send(201);
    })
  })
})

//Get user from token
app.get('/user', function(req, res) {
    var token = req.headers['x-auth'];
    var auth = jwt.decode(token, secretKey);
    //pull user info from database
    User.findOne({username: auth.username}, function (err, user){
      res.json(user);
    })
})



app.listen(3000);
