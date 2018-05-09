const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
const jwt = require('jsonwebtoken');
const config = require('../config/database');
const User = require('../models/user');
const async = require('async');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
router.post('/register', (req, res, next) => {
    let newUser = new User({
      name: req.body.name,
      email: req.body.email,
      password: req.body.password
    });
    User.getUserByEmail(newUser.email, (err,user)=> {
      if(err) throw err;
      if(user){
        return res.json({success:false,message:'User Already registered'});
      }
      User.addUser(newUser, (err, user) => {
        if(err){
          res.json({success: false, message:'Failed to register user'});
        } else {
          res.json({success: true, message:'User registered'});
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
      return res.json({success: false, message: 'User not found'});
    }

    User.comparePassword(password, user.password, (err, isMatch) => {
      if(err) throw err;
      if(isMatch){
        const token = jwt.sign({data: user}, config.secret, {
          expiresIn: 172800 //2 Days
        });

        res.json({
          success: true,
          token: `Bearer ${token}`,
          user: {
            id: user._id,
            name: user.name,
            email: user.email,
            profile_url: user.profile_url
          }
        });
      } else {
        return res.json({success: false, message: 'Wrong password'});
      }
    });
  });
  });
  router.post('/change-password',(req, res, next)=>{
    const id = req.body.id;
    const oldPassword = req.body.oldPassword;
    const newPassword = req.body.newPassword;
     
    User.getUserById(id, (err, user)=>{
      if(err) throw err;
      if(user) {
        User.comparePassword(oldPassword, user.password, (err, isMatch)=> {
          if(err) throw err;
          if(isMatch) {
            user.password = newPassword;
            bcrypt.genSalt(10, (err, salt) => {
              bcrypt.hash(user.password, salt, (err, hash) => {
                if(err) throw err;
                user.password = hash;
                user.save((err, user) => {
                  if(err){
                    res.json({success: false, message:'Failed to update password'});
                  } else {
                    res.json({success: true, message:'Updated Password'});
                  }
                });
              });
            });
          } else {
            return res.json({success: false, message: "Old Password Wrong"});
          }
         });
    }
     });

});
router.post('/update-profile', (req, res, next)=> {
  const id = req.body.id;
  const name = req.body.name;
  const profile_url = req.body.profile_url;
 User.getUserById(id, (err, user)=>{
   if (err) {
   if(!user) {
     res.json({status: false, message: 'User id wrong'});
   }
   } else {
    user.name = name;  
    user.profile_url = profile_url;
    user.save((err, user) => {
     if(err){
       res.json({success: false, message:'Failed to update profile url'});
     } else {
       res.json({success: true, message:'Profile url updated'});
     }
   });
   }
    
 });
 
});

router.get('/validate', passport.authenticate('jwt', {session:false}), (req, res, next) => {
  res.json({success: true});
});

router.get('/get-profile', (req, res, next)=> {
  const id = req.query.id;
  User.getUserById(id, (err, user)=> {
    if (err) throw err;
    if(user) {
      res.json({
        name: user.name,
        email: user.email,
        profile_url: user.profile_url
      });
    }
  });
});


router.post('/forgot', function(req, res, next) {
  async.waterfall([
    function(done) {
      crypto.randomBytes(5, function(err, buf) {
        var token = buf.toString('hex');
        done(err, token);
      });
    },
    function(token, done) {
      User.findOne({ email: req.body.email }, function(err, user) {
        if (!user) {
         return res.json({success: false, message: 'Email Does Not Exist'});
        }

        user.password = token;
        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(user.password, salt, (err, hash) => {
            if(err) throw err;
            user.password = hash;
            user.save((err, user) => {
              if(err) throw err;
              done(err, token, user);
            });
          });
        });
      });
    },
    function(token, user, done) {
      var smtpTransport = nodemailer.createTransport({
        service: 'Gmail', 
        auth: {
          user: process.env.EMAIL,
          pass: process.env.GMAIL_PASSWORD
        }
      });
      var mailOptions = {
        to: user.email,
        from: process.env.EMAIL,
        subject: 'Rail-App Password Reset',
        text: 'You are receiving this because you (or someone else) have requested the reset of the password for your Rail-App account.\n\n' +
          'Please use the following password to login to your account :-\n\n' + token + '\n\n' 
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        if (err) {
          res.json({success: false, message: 'failed due to internal error'});
        } else {
        res.json({success: true, message: 'An e-mail has been sent to ' + user.email + ' with a new password.'});
        }
        done(err, 'done');
      });
    }
  ], function(err) {
    if (err) {
    console.log(err);
    }
    
  });
});

router.post('/bug', (req, res, next)=> {
  const email = req.body.email;
  const message = req.body.message;
  User.findOne({email: email}, (err, user)=> {
    if(!user) {
      return res.status(404).json({success: false, message: 'User not found'});
    } else {
      let smtpTransport = nodemailer.createTransport({
        service: 'Gmail', 
        auth: {
          user: process.env.EMAIL,
          pass: process.env.GMAIL_PASSWORD
        }
      });
      let mailOptions = {
        to: process.env.EMAIL,
        from: process.env.EMAIL,
        subject: 'Rail-App Bug',
        text: 'The User ' + user.name + ' with email '+ email + ' has reported the following bug:-\n ' + message + '\n'
      };
      smtpTransport.sendMail(mailOptions, (err) => {
        if (err) {
          res.json({success: false, message: 'Failed to report bug'});
        } else {
        res.json({success: true, message: 'Your Bug has been reported'});
        }
      });
    }
  });
});
module.exports = router;
