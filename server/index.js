const express = require('express')
const app = express()
const port = 5000

const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const { User } = require('./models/User');
const { auth } = require('./middleware/auth');
const config = require("./config/key")

//application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({extended: true}));

//application/json
app.use(bodyParser.json());
app.use(cookieParser());


const mongoose = require('mongoose')
mongoose.connect(config.mongoURI, {
  useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true, useFindAndModify: false
}).then(() => console.log('MongoDB Connected'))
  .catch(err => console.log(err))

app.get('/', (req, res) => {
  res.send('Hello World! This is nodemon start')
})



app.get('/api/hello', (req, res) => res.send('Hello World!~~ '))

app.post('/api/register', (req, res) => {
  // register details
  // save details to DB
  const user = new User(req.body)

  user.save((err, userInfo) => {
    if(err) return res.json({success: false, err})
    return res.status(200).json({
      success: true
    })
  })
})

app.post('/api/user/login', (req, res) => {
  // finding request email in DB
  User.findOne({ email: req.body.email }, (err, user) => {
    if(!user) {
      return res.json({
        loginSuccess: false,
        message: "No User as matching in you provide email."
      })
    }

    // check password
    user.comparePassword(req.body.password, (err, isMatch) => {
      if(!isMatch) 
        return res.json({ loginSuccess: false, message: "Wrong password"})

      user.generateToken((err, user) => {
        if(err) return res.status(400).send(err)
        
        // save token cookie or localStorage
        res.cookie("x_auth", user.token)
        .status(200)
        .json({ loginSuccess: true, userId: user._id})
      })
    })
  })
})

app.get('/api/user/auth', auth ,(req, res) => {
  res.status(200).json({
    _id: req.user._id,
    isAdmin: req.user.role === 0 ? false : true,
    isAuth: true,
    email: req.user.email,
    name: req.user.name,
    lastname: req.user.lastname,
    role: req.user.role,
    image: req.user.image
  })
})

app.get('/api/user/logout', auth, (req, res) => {
  User.findOneAndUpdate({ _id: req.user._id}, 
    { token: ''}, (err, user) => {
      if(err) return res.json({ success: false, err});
      return res.status(200).send({ success: true })
    })
})

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`)
})