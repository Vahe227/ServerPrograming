import express from "express";
import session from "express-session";
import path from "path";
import bcrypt from "bcrypt";
import passport from "passport";
import passportLocal from "passport-local";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();
const server = express();
const __dirname = path.resolve();

server.use(express.json());
server.use(express.urlencoded({ extended: true }));

server.use(session({
  secret: process.env.MY_SESSION_SECRET || "your_default_secret",
  resave: false,
  saveUninitialized: false
}));

server.use(express.static(path.join(__dirname, 'public')));
server.use("/views", express.static(path.join(__dirname, "views")));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id: Number(id) } });
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

server.use(passport.initialize());
server.use(passport.session());

passport.use(new passportLocal.Strategy({
  usernameField: "email"
}, async (email, password, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return done(null, false, { message: "The Email Is Incorrect" });
    }
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return done(null, false, { message: "The Password Is Incorrect" });
    }
    return done(null, user);
  } catch (error) {
    return done(error);
  }
}));

function checkAuthenticated(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.redirect("/login");
  }
  next();
}

function checkNotAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return res.redirect("/");
  }
  next();
}

server.get("/registrator", checkNotAuthenticated, (req, res) => {
  res.sendFile(path.resolve("views/registrator.html"));
});

server.post("/registrator", async (req, res) => {
  const { name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const existingUser = await prisma.user.findUnique({ where: { email } });
  if (existingUser) {
    return res.redirect("/views/exits.html");
  }

  await prisma.user.create({
    data: {
      name,
      email,
      password: hashedPassword
    }
  });
  res.redirect("/login");
});

server.get("/login", checkNotAuthenticated, (req, res) => {
  res.sendFile(path.resolve("views/login.html"));
});

server.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/login"
}));

server.use(checkAuthenticated);

server.get("/", (req, res) => {
  res.sendFile(path.resolve("views/log.html"));
});

server.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) { return next(err); }
    res.redirect("/login");
  });
});

const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
