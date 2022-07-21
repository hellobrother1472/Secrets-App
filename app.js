//jshint esversion:6
require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const { default: mongoose } = require("mongoose");
const session = require('express-session')
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app = express();
app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session({   // Initializing a session
    secret: process.env.SECRET, // Key which is used to sign the session ID cookie. And after that session ID is checked
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());  // Initializing the passport
app.use(passport.session());  // Tell our app to use passport for setting our session


// Database
mongoose.connect("mongodb+srv://"+process.env.MONGO_USERNAME+":"+process.env.MONGO_PASSWORD+"@cluster0.aen287c.mongodb.net/userDB");
const userSchema = mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret : String
});

userSchema.plugin(passportLocalMongoose); // Adding it as a plugin as it simplifies building username and password login with Passport.

userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);


// Below code are because of passportLocalMongoose as because of that we can create strategy, serialize and deserialize in just 3 lines of code.
passport.use(User.createStrategy());  // creating local strategy which uses authentication by username and password

passport.serializeUser(function (user, done) {
    done(null, user.id);
    // where is this user.id going? Are we supposed to access this anywhere?
});

// used to deserialize the user
passport.deserializeUser(function (id, done) {
    User.findById(id, function (err, user) {
        done(err, user);
    });
});

passport.use(new GoogleStrategy({    // Using google strategy
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id }, function (err, user) {  // findorcreate is a psuedo code telling to use this type of fucntionality so we can either do it manually or use npm pacakage(we are using a npm package).
            return cb(err, user);
        });
    }
));


app.route("/")
    .get((req, res) => {
        res.render("home");
    })

app.route("/auth/google")
    .get(passport.authenticate('google', { scope: ['profile'] }));


app.route("/auth/google/secrets")
    .get(passport.authenticate('google', { failureRedirect: '/login' }),
        function (req, res) {
            // Successful authentication, redirect home.
            res.redirect('/secrets');
        });

app.route("/register")
    .get((req, res) => {
        res.render("register");
    })

    .post((req, res) => {
        // Here the .register meathod( of passport-local-mongoose) stores the username password if their is no errors just by using meathod. Their is not necessary to use any other thing here as we are using authentication here
        User.register({ username: req.body.username }, req.body.password, (err, user) => {
            if (err) {
                console.log(err);
                res.redirect("/register");
            } else {
                //  By using .authenticate we are authenticating with a local type of authentication(check kiya firr thappa lga diya ki verified hai) the request which set the req.user to authenticated and a session is started and cookies gets delivered.
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets")
                });
            }
        })


    });

app.route("/login")
    .get((req, res) => {
        res.render("login");
    })

    .post((req, res) => {

        const user = new User({
            username: req.body.username,
            password: req.body.password
        });

        // Check user in database and if no error occurs we authenticate(check kiya firr thappa lga diya ki verified hai) the request which set the req.user to authenticated and a session is started and cookies gets delivered.
        req.login(user, (err) => {
            if (err) {
                console.log(err);
            } else {
                passport.authenticate("local", { failureRedirect: '/login' })(req, res, function () {
                    res.redirect("/secrets");
                });
            }
        })
    })

app.route("/secrets")

    .get((req, res) => {

        User.find({secret:{$ne :null}}, (err,foundUser)=>{
            if(!err){
                res.render("secrets",{userWithSecrets : foundUser})
            } else{
                console.log(err);
            }
        })

    })


app.route("/logout")
    .get((req, res) => {
        req.logout((err) => {
            if (err) {
                console.log(err);
            } else {

                res.redirect('/');
            }
        });
    })

app.route("/submit")
    .get((req, res) => {
        // Here if user is authenticated then we will render secret page otherwise we will tell them to login
        if (req.isAuthenticated()) {
            res.render("submit");
        } else {
            res.redirect("/login")
        }
    })

    .post((req,res)=>{
        const userSecret = req.body.secret;

        User.findById(req.user.id,(err,foundOne)=>{
            if(!err){
                foundOne.secret = userSecret;
                foundOne.save(()=>{
                    res.redirect("/secrets");
                })
            } else{
                console.log(err);
            }
        })
    })



app.listen(process.env.PORT || 3000, () => {
    console.log("This server is up and running on port 3000")
})

