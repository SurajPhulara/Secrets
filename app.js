//jshint esversion:6
import 'dotenv/config';
import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import session from 'express-session';
import passport from 'passport';
import passportLocalMongoose from 'passport-local-mongoose';
import findOrCreate from 'mongoose-findorcreate';
import ejs, { render } from 'ejs';
import passportGoogle from 'passport-google-oauth20';
const GoogleStrategy = passportGoogle.Strategy;

const app=express();
const PORT=3000;

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended:true
}))


app.use(session({
    secret:"session secret",
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(`mongodb+srv://admin-suraj:${process.env.MONGOPASS}@cluster0.8lrjh.mongodb.net/userDB`, {useNewUrlParser: true})
.then(()=>{
  console.log("connected to mongodb")
})
.catch(e=>console.log(e));


const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] })
const User = mongoose.model("User",userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.displayName });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://rocky-fjord-48507.herokuapp.com/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",(req,res)=>{
    res.render("home.ejs") 
    console.log("home")
})
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
});

app.get("/login",(req,res)=>{
    res.render("login.ejs")
    console.log("login")
})

app.get("/register",(req,res)=>{
    res.render("register.ejs")
    console.log("register")
})

app.get("/secrets", (req,res)=>{
    if( req.isAuthenticated() )
    {
      User.find({"secret":{$ne:null}}, (err, userfound)=>{
        if(err)
        {
          console.log(err);
        }
        else{
          res.render("secrets.ejs", {usersWithSecrets:userfound})
        }
      })
    }
    else{
        res.redirect("/register")
    }
})

app.get("/submit", (req,res)=>{
  if(req.isAuthenticated())
  {
    res.render("submit.ejs")
  }
  else{
    res.redirect("/register")
  }
})

app.get("/logout", function(req, res){
    req.logout();
    res.redirect("/");
});

app.post("/register", function(req, res){

    User.register({username: req.body.username}, req.body.password, function(err, user){
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function(){
        //   res.render("secrets.ejs");
          res.redirect("/secrets");
        });
      }
    });
  
  });

app.post("/login",(req,res)=>{
    // const email = req.body.username;
    // const password = req.body.password;
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err) {
        if (err) 
        { 
            console.log(err); 
        }
        else {
             passport.authenticate("local")(req, res, function(){
        //   res.render("secrets.ejs");
          res.redirect("/secrets");
        });   
        }
      });
   
})

app.post("/submit", (req,res)=>{
  const submittedSecret= req.body.secret;
  console.log(req.user.id)

  User.findById(req.user.id, (err, userfound)=>{
    if(err)
    {
      console.log(err)
    }
    else if(userfound)
    {
      userfound.secret=submittedSecret;
      userfound.save(()=>{
        res.redirect("/secrets")
      });
    }
  })
})


app.listen(process.env.PORT || PORT, ()=>(console.log("listening on port "+PORT)))

