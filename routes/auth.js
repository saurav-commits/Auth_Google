var express = require('express');
var passport = require('passport');
var GoogleStrategy = require('passport-google-oauth20').Strategy; // Import the correct package
var db = require('../db');

var router = express.Router();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env['GOOGLE_CLIENT_ID'],
      clientSecret: process.env['GOOGLE_CLIENT_SECRET'],
      callbackURL: '/oauth2/redirect/google',
      scope: ['profile'],
    },
    function verify(accessToken, refreshToken, profile, cb) {
      // Your verification logic
      // This function is called after a successful Google authentication
      // You can handle user data and store it in the database, if needed
      // For example, you can use the 'profile' object to get user information
      // and perform database operations based on the user's profile data

      // Example: Insert user into the database
      db.get(
        'SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?',
        [profile.provider, profile.id],
        function (err, row) {
          if (err) {
            return cb(err);
          }
          if (!row) {
            db.run('INSERT INTO users (name) VALUES (?)', [profile.displayName], function (err) {
              if (err) {
                return cb(err);
              }

              var id = this.lastID;
              db.run(
                'INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)',
                [id, profile.provider, profile.id],
                function (err) {
                  if (err) {
                    return cb(err);
                  }
                  var user = {
                    id: id,
                    name: profile.displayName,
                  };
                  return cb(null, user);
                }
              );
            });
          } else {
            db.get('SELECT * FROM users WHERE id = ?', [row.user_id], function (err, row) {
              if (err) {
                return cb(err);
              }
              if (!row) {
                return cb(null, false);
              }
              return cb(null, row);
            });
          }
        }
      );
    }
  )
);

router.get('/login', function (req, res, next) {
  res.render('login');
});

router.get('/login/federated/google', passport.authenticate('google'));

router.get('/oauth2/redirect/google', passport.authenticate('google', {
  successRedirect: '/',
  failureRedirect: '/login',
}));

router.post('/logout', function(req, res, next) {
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
  });

module.exports = router;
