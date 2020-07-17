require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

// Level 6 authentication - Google OAuth Security (Third Party Security)
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

// Level 4 authentication - hash function with salting
// const bCryptjs = require("bcryptjs");
// const saltRounds = 10;

// Level 3 authentication - hash function
// const md5 = require("md5");

// Level 2 authentication - data encryption
// const encrypt =  require("mongoose-encryption");

const app = express();
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.set('view engine', 'ejs');

// Level 5 authentication - passport and express-session

app.use(session({
	secret: "Anime is my life.",
	resave: false,
	saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set('useCreateIndex', true);

const userSchema = new mongoose.Schema({
	// username: {
	// 	type: String,
	// 	required: true
	// },
	email: String,
	password: String,
	googleId: String,
	facebookId: String,
	secret: String
});

// Level 6 authentication - Google OAuth Security (Third Party Security)
userSchema.plugin(findOrCreate);

// Level 5 authentication - passport and express-session
userSchema.plugin(passportLocalMongoose);

// Level 2 authentication - data encryption
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

const User = new mongoose.model("User", userSchema);

// Level 5 authentication - passport and express-session
passport.use(User.createStrategy());
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

// Level 6 authentication - Google OAuth Security (Third Party Security)
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

// For Google authentication
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// For Facebook authentication
passport.use(new FacebookStrategy({
    clientID: process.env.FB_ID,
    clientSecret: process.env.FB_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets",
    profileFields: ['id', 'displayName', 'photos'],
    enableProof: true
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


//--------------------------------------- Home Page ------------------------------------------

app.get("/", function(req,res) {
	res.render("home");
});


//--------------------------------------- About Page ------------------------------------------

app.get("/about", function(req,res) {
	res.render("about");
});


//--------------------------------------- Contact Page ------------------------------------------

app.get("/contact", function(req,res) {
	res.render("contact");
});


//--------------------------------------- Google Page ------------------------------------------

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);
app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);


//--------------------------------------- Facebook Page ------------------------------------------

app.get("/auth/facebook",
  passport.authenticate("facebook")
);
app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);


//--------------------------------------- Login Page ----------------------------------------

app.route("/login")
.get(function(req,res) {
	res.render("login");
})
.post(function(req,res) {

	// Level 5 authentication - passport and express-session

	const newUser = new User({
		username: req.body.username,
		password: req.body.password
	});
	req.login(newUser, function(err) {
		if(err) {
			console.log(err);
			res.send("Incorrect email or password.");
		} else {
			passport.authenticate("local")(req, res, function() {
				res.redirect("/secrets");
			});
		}
	});


	// Level 4 authentication - hash function with salting (bcrypt)

	// const username = req.body.username;
	// const password = req.body.password;
	// User.findOne({username: username}, function(err, foundUser) {
	// 	if(err) {
	// 		console.log(err);
	// 	} else {
	// 		if(foundUser) {
	// 			bCryptjs.compare(password, foundUser.password, function(err, result) {
	// 				if(result === true) {
	// 					res.render("secrets");
	// 				} else {
	// 					res.send("Incorrect password.");
	// 				}
	// 			});
	// 		} else {
	// 			res.send("Incorrect Username.");
	// 		}
	// 	}
	// });


	// Level 3 authentication - hash function

	// const username = req.body.username;
	// const password = md5(req.body.password);
	// User.findOne({username: username}, function(err, foundUser) {
	// 	if(err) {
	// 		console.log(err);
	// 	} else {
	// 		if(foundUser) {
	// 			if(foundUser.password === password) {
	// 				res.render("secrets");
	// 			} else {
	// 				res.send("Incorrect password.");
	// 			}
	// 		} else {
	// 			res.send("Incorrect Username.");
	// 		}
	// 	}
	// });
});


//--------------------------------------- Secret Page ------------------------------------------

app.get("/secrets", function(req,res) {

	// Level 5 authentication - passport and express-session
	
	// if(req.isAuthenticated()){
	// 	res.render("secrets");
	// } else {
	// 	res.redirect("/login");
	// }
	User.find({"secret": {$ne: null}}, function(err, foundUsers) {
		if(err) {
			console.log(err);
		} else {
			if(foundUsers) {
				res.render("secrets", {usersWithSecrets: foundUsers});
			} else {
				res.render("secrets");
			}
		}
	});
});


//--------------------------------------- Submit Page ------------------------------------------

app.route("/submit")
.get(function(req, res) {
	if(req.isAuthenticated()){
		res.render("submit");
	} else {
		res.redirect("/login");
	}
})
.post(function(req, res) {
	const data = req.body.secret;
	User.findById(req.user.id, function(err, foundUser) {
		if(err) {
			console.log(err);
		} else {
			if(foundUser) {
				foundUser.secret = data;
				foundUser.save(function() {
					res.redirect("/secrets");
				});
			} else {
				res.redirect("/login");
			}
		}
	});
});


//--------------------------------------- LogOut Page ------------------------------------------

app.get("/logout", function(req,res) {
	
	// Level 5 authentication - passport and express-session

	req.logout();
	res.redirect("/");
});


//--------------------------------------- Register Page ----------------------------------------

app.route("/register")
.get(function(req,res) {
	res.render("register");
})
.post(function(req,res) {

	// Level 5 authentication - passport and express-session
	
	User.register({username: req.body.username}, req.body.password, function(err, user) {
		if(err) {
			console.log(err);
			res.redirect("/register");
			// res.send(alert("Something went wrong. Please try again!"));
		} else {
			passport.authenticate("local")(req, res, function() {
				res.redirect("/secrets");
			});
		}
	});


	// Level 4 authentication - hash function with salting (bcrypt)

	// bCryptjs.hash(req.body.password, saltRounds, function(err, hash) {
	// 	const newUser = new User({
	// 		username: req.body.username,
	// 		password: hash
	// 	});
	// 	newUser.save(function(err) {
	// 		if(!err) {
	// 			console.log("User successfully register to the database.");
	// 			res.render("secrets");
	// 		} else {
	// 			console.log(err);
	// 		}
	// 	});
	// });


	// Level 3 authentication - hash function
	
	// const newUser = new User({
	// 	username: req.body.username,
	// 	password: md5(req.body.password)
	// });
	// newUser.save(function(err) {
	// 	if(!err) {
	// 		console.log("User successfully register to the database.");
	// 		res.render("secrets");
	// 	} else {
	// 		console.log(err);
	// 	}
	// });
});


app.listen(process.env.PORT || 3000, function() {
	console.log("Server is working at port 3000.");
});

