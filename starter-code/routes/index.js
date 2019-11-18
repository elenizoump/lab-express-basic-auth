"use strict";

const {
  Router
} = require("express");
const router = Router();
const User = require("./../models/user");
const bcrypt = require("bcrypt");
const routeGuard = require('./route-guard');

router.get("/", (req, res, next) => {
  res.render("index", {
    title: "Hello World!"
  });
});

router.get("/sign-up", (req, res, next) => {
  res.render("sign-up");
});

router.post("/sign-up", (req, res, next) => {
  const {
    name,
    password
  } = req.body;
  bcrypt
    .hash(password, 10)
    .then(hash => {
      return User.create({
        name,
        passwordHash: hash
      });
    })
    .then(user => {
      console.log("Created user", user);
      req.session.user = user._id;
      res.redirect("/");
    })
    .catch(error => {
      next(error);
    });
});

router.get('/sign-in', (req, res, next) => {
  res.render('sign-in');
});

router.post('/sign-in', (req, res, next) => {
  let userId;
  const {
    name,
    password
  } = req.body;

  User.findOne({
      name
    })
    .then(user => {
      if (!user) {
        // If no user was found, return a rejection with an error
        // that will be sent to the error handler at the end of the promise chain
        return Promise.reject(new Error("There's no user with that name."));
      } else {
        // If there is an user,
        // save their ID to an auxiliary variable
        userId = user._id;
        // Compare the password with the salt + hash stored in the user document
        return bcrypt.compare(password, user.passwordHash);
      }
    })
    .then(result => {
      if (result) {
        // If they match, the user has successfully been signed up
        req.session.user = userId;
        res.redirect('/');
      } else {
        // If they don't match, reject with an error message
        return Promise.reject(new Error('Wrong password.'));
      }
    })
    .catch(error => {
      next(error);
    });
});

router.get('/private', routeGuard, (req, res, next) => {
  res.render('private');
});

router.get('/main', routeGuard, (req, res, next) => {
  res.render('private');
});
module.exports = router;