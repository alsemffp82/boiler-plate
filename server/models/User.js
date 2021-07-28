const mongoose = require('mongoose');
// bcrypt 
const bcrypt = require('bcrypt');
const saltRounds = 10;
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
  name: {
    type: String,
    maxlength: 50
  },
  email: {
    type: String,
    trim: true,
    unique: true
  },
  password: {
    type: String,
    minlength: 5
  },
  lastname: {
    type: String,
    maxlength: 50
  },
  role: {
    type: Number,
    default: 0
  },
  image: String,
  token: {
    type: String
  },
  tokenExp: {
    type: Number
  }
})

userSchema.pre('save', function( next ) {
  let user = this;

  if(user.isModified('password')) {
    // encrypt password
    bcrypt.genSalt(saltRounds, function(err, salt) {
      if(err) return next(err)
      bcrypt.hash(user.password, salt, function(err, hash) {
          // Store hash in your password DB.
          if(err) return next(err)
          user.password = hash
          next()
      });
    });
  } else next()
})

userSchema.methods.comparePassword = function(plainPassword, callback) {
  //plainpassword 1234567  encrypt password $2b$10$55mPC9dl2.EV/j9qf9JtuusMhcK5sw1EOyjxbHGb37dUOdFQAmpDq
  bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
    if(err) return callback(err);
    callback(null, isMatch);
  })
}

userSchema.methods.generateToken = function(callback) {
  let user = this;
  // jsonwebtoken create token
  let token = jwt.sign(user._id.toHexString(), 'secretToken')

  user.token = token
  user.save(function(err, user) {
    if(err) return callback(err);
    callback(null, user);
  })
}

userSchema.statics.findByToken = function(token, callback) {
  let user = this;

  jwt.verify(token, 'secretToken', function(err, decoded) {
    user.findOne({"_id": decoded, "token": token}, function(err, user){
      if(err) return callback(err);
      callback(null, user);

    })
  })
}

const User = mongoose.model('User', userSchema)

module.exports = { User }