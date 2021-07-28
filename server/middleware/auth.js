const { User } = require('../models/User');

let auth = (req, res, next) => {
  let token = req.cookies.x_auth;
  //get token from clien tocken
  User.findByToken(token, (err, user) => {
    if(err) throw err;
    if(!user) return res.json({ isAuth: false, error: true })

    req.token = token;
    req.user = user;
    next();
  })
  //decrypt token to id
  // if id is exist okay
}

module.exports = { auth };