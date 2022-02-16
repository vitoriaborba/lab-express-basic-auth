const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const saltRounds = 10;

const User = require('../models/User.model');

const router = require('express').Router();

router.get('/signup', (req, res, next) => {
    res.render('auth/signup')
})

router.post('/signup', (req, res, next) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        res.render('auth/signup', {
          errorMessage: 'All fields are required, please provide your username, email and password',
        });
        return;
      }
    bcrypt
      .genSalt(saltRounds)
      .then((salt) => bcrypt.hash(password, salt))
      .then((hashedPassword) => {
        return User.create({ username, email, passwordHash: hashedPassword });
      })
      .then(() => {
        res.redirect('/profile');
      })
       .catch((err) => {
      if (err instanceof mongoose.Error.ValidationError) {
        res.status(500).render('auth/signup', { errorMessage: err.message });
      } else {
        next(err);
      }
    });
  });

router.get('/login', (req, res, next) => {
    res.render('auth/login')
})

router.post('/login', (req, res, next) => {
    const { email, password } = req.body;
  
    if (!email || !password) {
      res.render('auth/login', { errorMessage: 'Please provide both email and password' });
      return;
    }
  
    User.findOne({ email }).then((user) => {
      if (!user) {
        res.render('auth/login', { errorMessage: 'Email not found.' });
        return;
      } else if (bcrypt.compareSync(password, user.passwordHash)) {
        req.session.currentUser = user;
        console.log('req session', req.session);
        res.render('profile', { user });
      } else {
        res.render('auth/login', { errorMessage: 'Incorrect password' });
      }
    });
  });




module.exports = router;