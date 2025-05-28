import express from "express";
import session from "express-session";
import path from "path";
import bcrypt from "bcrypt";
import passport from "passport";
import passportLocal from "passport-local";

let users = [];

const server  = express();
const __dirname = path.resolve();
server.use(express.json());
server.use(express.urlencoded({extended: true}));
server.use(session({
    secret: process.env.MY_SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
server.use(express.static(path.join(__dirname, 'public'))); 

passport.serializeUser((user,done) => {
    done(null,user.id);
});

passport.deserializeUser((id,done) => {
    done(null,users.find((user) => user.id === id))
});

server.use(passport.initialize());
server.use(passport.session());
passport.use(new passportLocal.Strategy({
    usernameField: "email"
},async (email,password,done) => {
    const user = users.find((user) => user.email === email);
    if(user === undefined){
        done(null,null,{message: "The Email is Incorect"});
    };
    if(await bcrypt.compare(password, user.password)){
        return done(null,user);
    };
    done(null,null,{message: "The Password is Incorect"});

}));


server.get("/registrator",checkNotAuthinucated,(req, res) => {
    res.sendFile(path.resolve("views/registrator.html"));
});

server.post("/registrator",async (req, res) => {
    const {name,email,password} = req.body;
    const HandlerSWD = await bcrypt.hash(password,10);

    users.push({
        id: `${Date.now()}_${Math.random()}`,
        name,
        email,
        password: HandlerSWD
    });
    res.redirect("/login");
});

server.get("/login",checkNotAuthinucated,(req, res) => {
    res.sendFile(path.resolve("views/login.html"));
});

server.post("/login",passport.authenticate("local",{
    successRedirect: "/",
    failureRedirect: "/login"
}));

server.use(checkAuthinucated)

server.get("/",(req,res) => {
    res.sendFile(path.resolve("views/log.html"));
});

server.get("/logout", (req, res, next) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect("/login");
    });
});


function checkAuthinucated(req,res,next){
    if(req.isAuthenticated() === false){
        return res.redirect("/login");
    };
    next();
};

function checkNotAuthinucated(req,res,next){
    if(req.isAuthenticated() === true){
        return res.redirect("/");
    };
    next();
};

server.listen(process.env.PORT, () => {
    console.log("Server running on http://localhost:3001");
});