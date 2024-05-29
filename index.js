import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import pg from "pg";
import bcrypt from "bcryptjs";
import passport from "passport";
import session from "express-session";
import { Strategy } from "passport-local";

const app = express();
const port = 3000;
const saltRounds = 10;

dotenv.config();
const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 6 // 6 hours
    }
}))

app.use(passport.initialize());
app.use(passport.session());

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
}

var globalMessage = {
    type: "",
    content: "",
    subcontent: "",
    setMessage(type, content, subcontent) {
        this.type = type;
        this.content = content;
        this.subcontent = subcontent;
    },
    getMessage() {
        const temp = { ... this };
        this.type = this.content = this.subcontent = "";
        return temp;
    }
};

// HOME
app.get("/", (req, res) => {
    res.render("home.ejs");
})

app.get("/login", (req, res) => {
    res.render("home_login.ejs", { message: globalMessage.getMessage() });
})

app.get("/register", (req, res) => {
    res.render("home_register.ejs", { message: globalMessage.getMessage() });
})

// AUTH
app.get("/home", (req, res) => {
    res.render("auth_home.ejs");
})

// REGISTER, LOGIN, LOGOUT POST ROUTE

app.post("/logout", ensureAuthenticated, (req, res) => {
    req.logout((err) => {
        if (err) {
            console.error(err);
            return res.sendStatus(500); // Internal Server Error
        }

        res.clearCookie('connect.sid'); // Clear the session cookie
        res.redirect("/");
    })
})

app.post("/register-post", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const password_confirmation = req.body.password_confirmation;

    try {
        const checkUnique = await db.query("SELECT * FROM users WHERE username = $1", [username]);

        if (checkUnique.rowCount > 0) {
            globalMessage.setMessage("danger", "Username already exist", "Try using a different username");
            res.redirect("/register");
        } else {
            if (password !== password_confirmation) {
                globalMessage.setMessage("danger", "Password doesn't match", "Make sure the password confirmation matches the password");
                res.redirect("/register");
            }
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.log(err);
                } else {
                    const result = await db.query("INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING *", [username, hash]);
                    const user = result.rows[0];

                    req.login(user, (err) => {
                        console.log(err);
                        globalMessage.setMessage("success", "Account created successfully", "You can start chatting now");
                        res.redirect("/home");
                    })
                }
            })
        }
    } catch (error) {
        console.log(error);
    }
})

app.post("/login-post", passport.authenticate("local", {
    successRedirect: "/home",
    failureRedirect: "/login"
}));

passport.use(
    "local",
    new Strategy(
        async (username, password, done) => {
            try {
                const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
                if (result.rowCount === 0) {
                    globalMessage.setMessage("danger", "Username doesn't exist", "Please make sure you entered the correct username");
                    return done(null, false);
                }

                const user = result.rows[0];
                const storedHashPassword = user.password_hash;

                bcrypt.compare(password, storedHashPassword, (err, isMatch) => {
                    if (err) {
                        return done(err);
                    } else if (isMatch) {
                        console.log(user);
                        globalMessage.setMessage("success", "Account logged in successfully", "Welcome back")
                        return done(null, user);
                    } else {
                        globalMessage.setMessage("danger", "Incorrect password", "Please make sure you entered the correct password");
                        return done(null, false);
                    }
                });
            } catch (error) {
                return done(error);
            }
        }
    )
);

passport.serializeUser((user, cb) => {
    cb(null, user);
})

passport.deserializeUser((user, cb) => {
    cb(null, user);
})

app.listen(port, () => {
    console.log(`Listening on port ${port}.`);
})