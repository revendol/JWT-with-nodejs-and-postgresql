//ENV file and package related code
const dotenv = require('dotenv');
dotenv.config();
//Express initialization
const express = require('express');
const app = express();
//Body parser
const parser = require('body-parser');
//JWT thing
const passport = require('passport');
const passportJWT = require('passport-jwt');
const JwtStrategy = passportJWT.Strategy;
const extractJWT = passportJWT.ExtractJwt;
const jwt = require('jsonwebtoken');
//Database related code
const knex = require('knex');
const knexDb = knex({client: 'pg',connection:{database: 'jwt_test',user:'postgres',password:'radoan151'}});
const bookshelf = require('bookshelf');
const securePassword = require('bookshelf-secure-password');
const db = bookshelf(knexDb);
db.plugin(securePassword);

//Create user model
const User = db.Model.extend({
    tableName: 'login_user',
    hasSecurePassword:true
});
//Options for JWT
const opts = {
    jwtFromRequest: extractJWT.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.SECRETE_OR_KEY
};

const strategy = new JwtStrategy(opts, (payload, next) => {
    //TODO: Get user from db
    User.forge({id: payload.id}).fetch().then(res => {
        next(null, res);
    });
});
passport.use(strategy);
app.use(passport.initialize());
//Use body parser
app.use(parser.urlencoded({
    extended: true
}));
app.use(parser.json());


app.get('/',(req, res) => {
    res.send('Hello world');
});

app.post('/seedUser',(req,res) => {
    const user = new User({
        email: "radoan@test.com",
        password: "password"
    });
    user.save().then(()=>{res.send('Ok')});
});

app.get('/protected',passport.authenticate('jwt',{session: false}), (req, res) => {
    res.send("I'm protected");
});

app.post('/getToken',(req, res) => {
    // if(!req.body.email || !req.body.password){
    //     return res.status(401).send('Fields are empty');
    // }
    var email = "radoan@test.com";
    var password = "password";
    User.forge({email: email}).fetch().then(result => {
        if(!result){
            return res.status(400).send("User not found");
        }

        result.authenticate(password).then(user => {
            const payload = {id: user.id};
            const token = jwt.sign(payload, process.env.SECRETE_OR_KEY);
            res.send(token);
        }).catch(err => {
            return res.status(401).send({err: err});
        });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT);