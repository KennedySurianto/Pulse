import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import pg from "pg";
import bcrypt from "bcryptjs";
import passport from "passport";
import cookieSession from "cookie-session";
import { Strategy } from "passport-local";
import multer from 'multer';
import { extname } from 'path';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs/promises';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const saltRounds = 10;
const { Pool } = pg;

dotenv.config();
const pool = new Pool({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
})

app.use(async (req, res, next) => {
    try {
        req.db = await pool.connect();
        res.on("finish", () => {
            req.db.release();
        })
        next();
    } catch (error) {
        next(error);
    }
})

app.use(cookieSession({
    name: "session",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60 * 6 // 6 hours
    }
}))

// Set up storage engine
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, path.join(__dirname, 'public', 'images')); // Destination folder for uploaded files
    },
    filename: (req, file, cb) => {
        // Generate unique filename
        cb(null, file.fieldname + '-' + Date.now() + extname(file.originalname));
    }
});

// Initialize multer
const upload = multer({ storage: storage });

app.use(passport.initialize());
app.use(passport.session());

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.set('view engine', 'ejs');
app.set('views', './views');

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
    if (req.isAuthenticated()) {
        res.redirect("/home");
    } else {
        res.render("home.ejs");
    }
})

app.get("/login", (req, res) => {
    res.render("home_login.ejs", { message: globalMessage.getMessage() });
})

app.get("/register", (req, res) => {
    res.render("home_register.ejs", { message: globalMessage.getMessage() });
})

// AUTH
app.get("/home", ensureAuthenticated, async (req, res) => {
    try {
        const friends = await req.db.query("SELECT * FROM friends f JOIN users u ON f.friend_id = u.user_id WHERE f.user_id = $1", [req.user.user_id]);

        res.render("auth_home.ejs", { message: globalMessage.getMessage(), friends: friends.rows, friendActive: true });
    } catch (error) {
        console.log(error);
        res.redirect("/");
    }
})

app.get("/pending", ensureAuthenticated, async (req, res) => {
    try {
        const pending = await req.db.query("SELECT f.user_id, u.username, u.profile_image_url FROM friends f JOIN users u ON u.user_id = f.user_id WHERE friend_id = $1 EXCEPT SELECT f.friend_id, u.username, u.profile_image_url FROM friends f JOIN users u ON u.user_id = f.friend_id WHERE f.user_id = $1", [req.user.user_id]);

        res.render("auth_pending.ejs", { message: globalMessage.getMessage(), pending: pending.rows, pendingActive: true });
    } catch (error) {
        console.log(error);
        res.redirect("/");
    }
})

app.get("/users", ensureAuthenticated, async (req, res) => {
    try {
        const users = await req.db.query("SELECT u.user_id, username, profile_image_url FROM users u WHERE u.user_id <> $1 AND u.user_id NOT IN (SELECT friend_id FROM friends WHERE user_id = $1)", [req.user.user_id]);
        res.render("auth_userlist.ejs", { users: users.rows, userActive: true });
    } catch (error) {
        console.log(error);
        res.redirect("/");
    }
})

app.get("/profile", ensureAuthenticated, async (req, res) => {
    try {
        res.render("auth_profile.ejs", { user: req.user, profileActive: true });
    } catch (error) {
        console.log(error);
        res.redirect("/");
    }
})

app.get("/chat/:friend_id", ensureAuthenticated, async (req, res) => {
    const friend_id = req.params.friend_id;
    try {
        let chatQuery = await req.db.query("SELECT DISTINCT p1.chat_id FROM participants p1 JOIN participants p2 ON p1.chat_id = p2.chat_id WHERE p1.user_id = $1 AND p2.user_id = $2", [req.user.user_id, friend_id]);

        const friendQuery = await req.db.query("SELECT user_id, username, profile_image_url FROM users WHERE user_id = $1", [friend_id]);
        const friend = friendQuery.rows[0];

        let messages;
        let finalChatId;
        if (chatQuery.rowCount > 0) {
            const chat_id = chatQuery.rows[0].chat_id;
            messages = await req.db.query("SELECT DISTINCT m.*, u.user_id, username, profile_image_url FROM messages m JOIN users u ON u.user_id = m.sender_id WHERE m.chat_id = $1", [chat_id]);
            finalChatId = chat_id;
        } else {
            await req.db.query("BEGIN;");
            const newChatQuery = await req.db.query("INSERT INTO chats DEFAULT VALUES RETURNING chat_id");
            const newChatId = newChatQuery.rows[0].chat_id;
            await req.db.query("INSERT INTO participants (chat_id, user_id) VALUES ($1, $2), ($1, $3)", [newChatId, req.user.user_id, friend_id]);
            await req.db.query("COMMIT;");
            messages = { rows: [] }; // Initialize messages to an empty array since there are no messages in a new chat
            finalChatId = newChatId;
        }
        res.render("auth_chat.ejs", { chat_id: finalChatId, messages: messages.rows, friend });
    } catch (error) {
        await req.db.query("ROLLBACK;");
        console.error(error);
        res.redirect("/");
    }
})

app.post("/search-user", ensureAuthenticated, async (req, res) => {
    const username = req.body.username;

    try {
        const users = await req.db.query("SELECT user_id, username, profile_image_url FROM users WHERE user_id <> $1 AND username ILIKE '%' || $2 || '%';", [req.user.user_id, username]);

        res.render("auth_userlist.ejs", { users: users.rows, userActive: true });
    } catch (error) {
        console.error(error);
        res.redirect("/");
    }
})

app.post('/upload-profile-picture', upload.single('picture'), ensureAuthenticated, async (req, res) => {
    // Access uploaded file details via req.file
    if (!req.file) {
        return res.status(400).send('No files were uploaded.');
    }
    // Construct the URL to the uploaded file
    const fileUrl = `${req.protocol}://${req.get('host')}/images/${req.file.filename}`;
    try {
        // Delete the previous profile image, if it exists
        if (req.user.profile_image_url && !req.user.profile_image_url.includes("https")) {
            const previousImagePath = req.user.profile_image_url.split('/').pop(); // Get the filename from the URL
            await fs.unlink(`public/images/${previousImagePath}`);
        }
        req.user.profile_image_url = fileUrl;
        await req.db.query("UPDATE users SET profile_image_url = $1 WHERE user_id = $2", [fileUrl, req.user.user_id]);
        res.redirect("/profile");
    } catch (error) {
        console.error(error);
        res.redirect("/")
    }
});

app.post("/remove-friend", ensureAuthenticated, async (req, res) => {
    const friend_id = parseInt(req.body.friend_id);

    try {
        await req.db.query("DELETE FROM friends WHERE user_id = $1 AND friend_id = $2", [req.user.user_id, friend_id]);

        res.redirect("/home");
    } catch (error) {
        console.log(error);
        res.redirect("/");
    }
})

app.post("/add-friend", ensureAuthenticated, async (req, res) => {
    const friend_id = parseInt(req.body.user_id);
    // console.log(friend_id);
    try {
        await req.db.query("INSERT INTO friends (user_id, friend_id) VALUES ($1, $2)", [
            req.user.user_id,
            friend_id
        ]);
        globalMessage.setMessage("success", "Friend added successfully", "Try chatting now");
        res.redirect("/home");
    } catch (error) {
        console.log(error);
        res.redirect("/");
    }
})

app.post("/message-post", async (req, res) => {
    const sender_id = parseInt(req.user.user_id);
    const content = req.body.content;
    const chat_id = parseInt(req.body.chat_id);
    const friend_id = parseInt(req.body.friend_id);

    try {
        await req.db.query("INSERT INTO messages (sender_id, content, chat_id) VALUES ($1, $2, $3)", [sender_id, content, chat_id]);

        res.redirect(`/chat/${friend_id}`);
    } catch (error) {
        console.log(error);
        res.redirect("/");
    }
})

// REGISTER, LOGIN, LOGOUT POST ROUTE
app.post('/logout', async (req, res, next) => {
    req.logout();
    req.session = null;
    res.clearCookie('app.session', process.env.SESSION_SECRET)
    res.clearCookie('app.session.sig', process.env.SESSION_SECRET)

    return res.redirect("/");
})

app.post("/register-post", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const password_confirmation = req.body.password_confirmation;

    try {
        const checkUnique = await req.db.query("SELECT * FROM users WHERE username = $1", [username]);

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
                    const result = await req.db.query("INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING *", [username, hash]);
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
        { passReqToCallback: true },
        async (req, username, password, done) => {
            try {
                const result = await req.db.query("SELECT * FROM users WHERE username = $1", [username]);
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

app.listen(process.env.PORT, '0.0.0.0', () => {
    console.log(`Listening on port ${process.env.PORT}.`);
})