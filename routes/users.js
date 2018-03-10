const express = require('express');
const router = express.Router();
const passport = require('passport');
const jwt = require('jsonwebtoken');
const config = require('../config/database');
const User = require('../models/user');

router.post('/register', (req, res, next) => {
    let newUser = new User({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password
    });
    User.getUserByEmail(newUser.email, (err,user)=> {
      if(err) throw err;
      if(user){
        return res.json({success:false,msg:'User Already registered'});
      }
      User.addUser(newUser, (err, user) => {
        if(err){
          res.json({success: false, msg:'Failed to register user'});
        } else {
          res.json({success: true, msg:'User registered'});
        }
      });
    });
   
  });

  router.post('/login',(req, res, next)=>{
  const email = req.body.email;
  const password = req.body.password;

  User.getUserByEmail(email, (err, user) => {
    if(err) throw err;
    if(!user){
      return res.json({success: false, msg: 'User not found'});
    }

    User.comparePassword(password, user.password, (err, isMatch) => {
      if(err) throw err;
      if(isMatch){
        const token = jwt.sign({data: user}, config.secret, {
          expiresIn: 172800 //2 Days
        });

        res.json({
          success: true,
          token: `Token is ${token}`,
          user: {
            id: user._id,
            name: user.name,
            email: user.email
          }
        });
      } else {
        return res.json({success: false, msg: 'Wrong password'});
      }
    });
  });
  });
  module.exports = router;
