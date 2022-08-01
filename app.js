require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
///////////PASSPORT AND SESSION///////////////// step 1/// 
// import all packages                                                              {
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
//-------------------------OAUTH2.0--------------------------------------------------------------//
const GoogleStrategy = require('passport-google-oauth20');
const FacebookStrategy = require('passport-facebook');
////                                                                                }


const app = express();
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

///////////PASSPORT AND SESSION///////////////// step 2///      
///// now use Session AND initialize PASSPORT, to use session init                  {
app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false,
}))
app.use(passport.initialize());
app.use(passport.session());
////                                                                                }

mongoose.connect("mongodb+srv://" + process.env.MONGO_KEY + "@cluster0.ctj2b.mongodb.net/" + process.env.DB_NAME, { useNewUrlParser: true });


const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
})
///////////PASSPORT AND SESSION///////////////// step 3///      
///// now use plugin passportLocalMongoose to connect mongoose and passport         { 
userSchema.plugin(passportLocalMongoose);
////                                                                                }

const User = new mongoose.model("user", userSchema);

///////////PASSPORT AND SESSION///////////////// step 4///      
/////  USING PASSPORT TO INTITIALIZE,CREATE COOKIE(serializeUser) and DESTROY COOKIE
/////  (deserializeUser) .All using passport only                                   { 
passport.use(User.createStrategy());

//--------------------------------------PASSPORT OAUTH2.0--------------------------------\\

passport.serializeUser(function (user, cb) {
    process.nextTick(function () {
        cb(null, { id: user.id, username: user.username });
    });
});

passport.deserializeUser(function (user, cb) {
    process.nextTick(function () {
        return cb(null, user);
    });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_G,
    scope: ['profile'],
    state: true
},
    function verify(accessToken, refreshToken, profile, cb) {
        // console.log(profile);

        User.findOne({
            googleId: profile.id
        }, function (err, user) {
            if (err) {
                return cb(err);
            }
            //No user was found... so create a new user with values from Facebook (all the profile. stuff)
            if (!user) {
                user = new User({
                    googleId: profile.id,
                    email: profile.displayName,
                    // email: profile.emails[0].value,
                    // password: profile.username,
                    provider: profile.provider,
                    //now in the future searching on User.findOne({'facebook.id': profile.id } will match because of this next line
                    // facebook: profile._json
                });
                user.save(function (err) {
                    if (err) console.log(err);
                    return cb(err, user);
                });
            } else {
                //found user. Return
                // console.log(user);
                return cb(err, user);
            }
        });
    }));



passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FB,
    clientSecret: process.env.CLIENT_SECRET_FB,
    callbackURL: process.env.CALLBACK_FB
},
    function (accessToken, refreshToken, profile, cb) {
        // console.log(profile);
        User.findOne({
            googleId: profile.id
        }, function (err, user) {
            if (err) {
                return cb(err);
            }
            //No user was found... so create a new user with values from Facebook (all the profile. stuff)
            if (!user) {
                user = new User({
                    googleId: profile.id,
                    email: profile.displayName,
                    // email: profile.emails[0].value,
                    // password: profile.username,
                    password: profile.provider,
                    //now in the future searching on User.findOne({'facebook.id': profile.id } will match because of this next line
                    // facebook: profile._json
                });
                user.save(function (err) {
                    if (err) console.log(err);
                    return cb(err, user);
                });
            } else {
                //found user. Return
                // console.log(user);
                return cb(err, user);
            }
        });
    }
));
////                                                                                }

app.get("/", (req, res) => {
    res.render("home", {});
})

app.get("/login", (req, res) => {
    res.render("login", {});
})

app.get("/register", (req, res) => {
    res.render("register", {});
})

//--------------------------------------PASSPORT OAUTH2.0--------------------------------\\
app.get('/auth/google', passport.authenticate('google'));
app.get('/auth/google/secrets', passport.authenticate(
    'google',
    { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect secrets.
        res.redirect('/secrets');
    }
);

app.get('/auth/facebook', passport.authenticate('facebook'));
app.get('/auth/facebook/secrets', passport.authenticate(
    'facebook',
    { failureRedirect: '/login' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    }
);

app.get("/secrets", (req, res) => {
    ///////////PASSPORT AND SESSION///////////////// step 6///  
    ///// Now, we will check every time if anyone wants to access "secrets" ,they must {
    ///// be authenticated or matched first and while you login and register we create 
    ///// a cookie which store the auth data ,and user dont need to again authrize 
    ///// until session timeout/brakout   

    // if (req.isAuthenticated()) {

    //     res.render("secrets", {});
    // } else {
    //     res.redirect("/login");
    // }


    User.find({ secret: { $ne: null } }, (err, userSecrets) => {
        if (err) { console.log(err); }
        else {
            res.render("secrets", { userSecret: userSecrets });
        }
    })
})

app.get("/logout", (req, res) => {
    req.logout(function (err) {
        if (err) { console.log(err); }
        res.redirect('/');
    });
})
app.post("/register", (req, res) => {
    ///////////PASSPORT AND SESSION///////////////// step 5///      
    ///// Since we have passportlocalmongoose ,we will use 'register' method to save 
    ///// data in DB, instead of 'save',passport and mongoose,i.e model,schema,DB,
    ///// session,cookie are connected internally                                       { 
    User.register(
        { username: req.body.username, active: false },/// pased username
        req.body.password,                             /// passed email
        function (err, user) {
            if (err) {
                console.log(err)
                res.redirect("/register");
            }
            else {
                passport.authenticate("local")(req, res, () => {
                    res.redirect("/secrets");
                })
            }
        });
    ////                                                                                }

})

app.post("/login", (req, res) => {
    ///////////PASSPORT AND SESSION///////////////// step 7///      
    ///// Since we have passportlocalmongoose ,we will use 'login' method to check user 
    ///// in DB, instead of 'findOne',to fecth DB                                       { 
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.logIn(user, (err) => {
        if (err) { console.log(err) }
        else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            })
        }
    })

})

app.get("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        res.render("submit", {});
    } else {
        res.redirect("/login");
    }
})

app.post("/submit", (req, res) => {
    if (req.isAuthenticated()) {
        User.findOne({ _id: req.user.id }, (err, result) => {
            if (err) { console.log(err); }
            else {
                if (result) {
                    result.secret = req.body.secret;
                    result.save(() => {
                        res.redirect("/secrets");
                    })
                }
            }
        })
    } else {
        res.redirect("/login");
    }
})
app.listen(process.env.PORT || 3000, () => {
    console.log("Server started");
})