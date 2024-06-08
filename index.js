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
import { Server } from 'socket.io';
import http from 'http';

const app = express();
const saltRounds = 10;
const { Pool } = pg;
const server = http.createServer(app);
const io = new Server(server);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
// Development
const pool = new Pool({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
})

// Production
// const pool = new Pool({
//     connectionString: process.env.POSTGRES_URL,
// })

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
        cb(null, path.join(__dirname, 'public/images/')); // Destination folder for uploaded files
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

// TEST
// app.get('/test', (req, res) => {
//     res.render('test_socket');
// });

// socket.io
io.on('connection', (socket) => {
    console.log('a user connected');

    // Join a chat room
    socket.on('join chat', (chat_id) => {
        socket.join(chat_id);
    });

    // Handle events (e.g., chat messages)
    socket.on('chat message', async (msg) => {
        // Extract message data from payload
        const { chat_id, content, sender_id } = msg;
        console.log('msg:', msg);

        try {
            const db = await pool.connect();

            // Insert message into the database
            const insertedMessage = await db.query("INSERT INTO messages (chat_id, content, sender_id) VALUES ($1, $2, $3) RETURNING *", [chat_id, content, sender_id]);

            // Check if any rows were inserted
            if (insertedMessage.rows.length > 0) {
                const messageId = insertedMessage.rows[0].message_id;

                // Retrieve the inserted message along with additional user information
                const message = await db.query("SELECT DISTINCT m.*, u.user_id, username, profile_image_url FROM messages m JOIN users u ON u.user_id = m.sender_id WHERE message_id = $1", [messageId]);

                // Check if the message was retrieved
                if (message.rows.length > 0) {
                    const messageToEmit = message.rows[0];
                    console.log('msgtoemit:', messageToEmit);

                    // Broadcast the message to all clients
                    io.emit('chat message', messageToEmit);
                } else {
                    console.error("Failed to retrieve the inserted message");
                }
            } else {
                console.error("No rows were inserted");
            }
            db.release();
        } catch (error) {
            console.error(error);
        }
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        console.log('user disconnected');
    });
});

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
        res.render("auth_profile.ejs", { user: req.user, profileActive: true, message: globalMessage.getMessage() });
    } catch (error) {
        console.log(error);
        res.redirect("/");
    }
})

app.post("/chat", ensureAuthenticated, async (req, res) => {
    req.session.friend_id = req.body.friend_id;
    console.log(req.session.friend_id)
    res.redirect("/chat");
})

app.get("/chat", ensureAuthenticated, async (req, res) => {
    const friend_id = req.session.friend_id;
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
            try {
                await req.db.query("BEGIN;");
                const newChatQuery = await req.db.query("INSERT INTO chats DEFAULT VALUES RETURNING chat_id");
                const newChatId = newChatQuery.rows[0].chat_id;
                await req.db.query("INSERT INTO participants (chat_id, user_id) VALUES ($1, $2), ($1, $3)", [newChatId, req.user.user_id, friend_id]);
                await req.db.query("COMMIT;");
                messages = { rows: [] }; // Initialize messages to an empty array since there are no messages in a new chat
                finalChatId = newChatId;
            } catch (error) {
                await req.db.query("ROLLBACK;");
                console.error(error);
                res.redirect("/");
            }
        }
        res.render("auth_chat.ejs", { chat_id: finalChatId, messages: messages.rows, friend, user: req.user });
    } catch (error) {
        console.error(error);
        res.redirect("/");
    }
})

app.get("/groups", ensureAuthenticated, async (req, res) => {
    const getGroupsQuery = `
            SELECT *
            FROM chats c
                JOIN groups g ON g.chat_id = c.chat_id
                JOIN participants p ON p.chat_id = c.chat_id
            WHERE p.user_id = $1;
        `;
    const getFriendsQuery = `
            SELECT u.user_id, username, profile_image_url 
            FROM friends f 
                JOIN users u ON u.user_id = f.friend_id 
            WHERE f.user_id = $1
        `;
    try {
        const groups = await req.db.query(getGroupsQuery, [req.user.user_id]);
        const friends = await req.db.query(getFriendsQuery, [req.user.user_id]);

        res.render("auth_groups.ejs", { groupActive: true, groups: groups.rows, friends: friends.rows });
    } catch (error) {
        console.error(error);
        res.redirect("/");
    }
})

// TODO: ganti group settings dari modal ke page baru
app.post("/group-settings", ensureAuthenticated, (req, res) => {
    const group_id = req.body.chat_id;
    req.session.group_id = group_id;
    res.redirect("/group-settings");
})

app.get("/group-settings", ensureAuthenticated, async (req, res) => {
    const group_id = req.session.group_id;
    console.log("chat_id: ", group_id);
    const getGroupQuery = `
        SELECT * FROM groups g
            JOIN group_leaders gl ON gl.chat_id = g.chat_id
        WHERE g.chat_id = $1;
    `;
    const checkParticipantQuery = `
        SELECT * FROM participants
        WHERE user_id = $1 AND chat_id = $2;
    `;
    const getGroupMembersQuery = `
        SELECT * FROM participants p
            JOIN users u ON u.user_id = p.user_id
        WHERE chat_id = $1;
    `;
    const getFriendsExceptMembersQuery = `
        SELECT f.friend_id, username, profile_image_url
        FROM friends f
            JOIN users u ON u.user_id = f.friend_id
        WHERE f.user_id = $1
            AND f.friend_id NOT IN (
                SELECT user_id FROM participants
                WHERE chat_id = $2
            );
    `;
    try {
        const checkUser = await req.db.query(checkParticipantQuery, [req.user.user_id, group_id]);
        if (checkUser.rowCount > 0) {
            const group = await req.db.query(getGroupQuery, [group_id]);
            const friends = await req.db.query(getFriendsExceptMembersQuery, [req.user.user_id, group_id]);
            console.log("friends except members: ", friends.rows);
            const members = await req.db.query(getGroupMembersQuery, [group_id]);
            // console.log("group.rows[0]: ", group.rows[0]);
            res.render("auth_group_settings.ejs", { group: group.rows[0], user: req.user, friends: friends.rows, members: members.rows });
        } else {
            res.redirect("/groups");
        }
    } catch (error) {
        console.error(error);
        res.redirect("/");
    }
})

app.post("/delete-group", ensureAuthenticated, async (req, res) => {
    const chat_id = req.body.chat_id;
    try {
        await req.db.query("DELETE FROM chats WHERE chat_id = $1", [chat_id]);
        res.redirect("/groups");
    } catch (error) {
        console.error(error);
        res.redirect("/");
    }
})

app.post("/group-chat", ensureAuthenticated, (req, res) => {
    const group_id = req.body.chat_id;
    req.session.group_id = group_id;
    res.redirect("/group-chat");
})

app.get("/group-chat", ensureAuthenticated, async (req, res) => {
    const group_id = req.session.group_id;
    const getMessagesQuery = `
        SELECT 
            message_id, content, m.created_at,
            chat_id, sender_id, user_id, username, profile_image_url
        FROM messages m
            JOIN users u ON u.user_id = m.sender_id
        WHERE m.chat_id = $1
        ORDER BY m.created_at ASC;
    `;
    const getGroupQuery = `
        SELECT * FROM groups g
            JOIN group_leaders gl ON gl.chat_id = g.chat_id
        WHERE g.chat_id = $1;
    `;
    const checkParticipantQuery = `
        SELECT * FROM participants
        WHERE user_id = $1 AND chat_id = $2;
    `;
    try {
        const checkUser = await req.db.query(checkParticipantQuery, [req.user.user_id, group_id]);
        if (checkUser.rowCount > 0) {
            const messages = await req.db.query(getMessagesQuery, [group_id]);
            const group = await req.db.query(getGroupQuery, [group_id]);
            // console.log("messages.rows: ", messages.rows);
            // console.log("group.rows[0]: ", group.rows[0]);
            res.render("auth_groupchat.ejs", { messages: messages.rows, group: group.rows[0], user: req.user });
        } else {
            res.redirect("/groups");
        }
    } catch (error) {
        console.error(error);
        res.redirect("/");
    }
})

app.post("/create-group", upload.single('picture'), ensureAuthenticated, async (req, res) => {
    let fileUrl = `${req.protocol}://${req.get('host')}/images/`;
    fileUrl += req.file ? req.file.filename : 'default2202.png';

    const { groupName, picture, ...members } = req.body;
    const memberIds = Object.keys(members).map(key => key.replace('member_', ''));

    const insertIntoChatsQuery = `
        INSERT INTO chats (chat_id) VALUES (DEFAULT) 
        RETURNING chat_id;
    `;
    const insertIntoGroupsQuery = `
        INSERT INTO groups (chat_id, group_name, group_image_url) VALUES ($1, $2, $3);
    `;
    const insertIntoGroupLeadersQuery = `
        INSERT INTO group_leaders (chat_id, user_id) VALUES ($1, $2);
    `;
    const insertIntoParticipantsQuery = `
        INSERT INTO participants (chat_id, user_id) VALUES ($1, $2);
    `;
    try {
        await req.db.query("BEGIN;");

        const newChat = await req.db.query(insertIntoChatsQuery);
        const chat_id = newChat.rows[0].chat_id;

        await req.db.query(insertIntoGroupsQuery, [chat_id, groupName, fileUrl]);
        await req.db.query(insertIntoGroupLeadersQuery, [chat_id, req.user.user_id]);
        await req.db.query(insertIntoParticipantsQuery, [chat_id, req.user.user_id]);

        for (const memberId of memberIds) {
            await req.db.query(insertIntoParticipantsQuery, [chat_id, memberId]);
        }

        await req.db.query("COMMIT;")
        res.redirect("/groups");
    } catch (error) {
        await req.db.query("ROLLBACK;");
        console.error(error);
        res.redirect("/");
    }
})

app.post('/add-members', ensureAuthenticated, async (req, res) => {
    const { chat_id, ...members } = req.body;
    const memberIds = Object.keys(members).map(key => key.replace('member_', ''));
    const insertIntoParticipantsQuery = `
        INSERT INTO participants (chat_id, user_id) VALUES ($1, $2);
    `;
    try {
        await req.db.query("BEGIN;");
        for (const memberId of memberIds) {
            await req.db.query(insertIntoParticipantsQuery, [chat_id, memberId]);
        }
        await req.db.query("COMMIT;");
        res.redirect("/group-settings");
    } catch (error) {
        await req.db.query("ROLLBACK;");
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
        if (req.user.profile_image_url && !req.user.profile_image_url.includes("default2201.png") && req.user.profile_image_url !== "https://picsum.photos/200") {
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
    const wasPending = req.body.wasPending;
    try {
        await req.db.query("INSERT INTO friends (user_id, friend_id) VALUES ($1, $2)", [
            req.user.user_id,
            friend_id
        ]);
        globalMessage.setMessage("success", "Friend added successfully", "Try chatting now");
        (wasPending) ? res.redirect("/pending") : res.redirect("/users");
    } catch (error) {
        console.log(error);
        res.redirect("/");
    }
})

app.post("/change-password", ensureAuthenticated, async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    try {
        const userPasswordHash = req.user.password_hash;
        const isMatch = await bcrypt.compare(currentPassword, userPasswordHash);

        if (!isMatch) {
            console.log("password incorrect")
            globalMessage.setMessage("danger", "Incorrect password", "Make sure you entered the correct password");
        } else if (newPassword.length < 8) {
            globalMessage.setMessage("danger", "Password invalid", "Make sure password is more than or equal to 8 characters");
        } else if (newPassword != confirmPassword) {
            globalMessage.setMessage("danger", "Password does not match", "Make sure the password match");
        } else {
            const salt = await bcrypt.genSalt(saltRounds);
            const hashedNewPassword = await bcrypt.hash(newPassword, salt);
            await req.db.query("UPDATE users SET password_hash = $1 WHERE user_id = $2", [
                hashedNewPassword,
                req.user.user_id
            ]);
            globalMessage.setMessage("success", "Password changed successfully", "Make sure to remember it");
        }
        res.redirect("/profile");
    } catch (error) {
        console.error(error);
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
            return res.redirect("/register");
        } else if (username.length > 15) {
            globalMessage.setMessage("danger", "Invalid username", "Make sure the username length is less than or equal to 15 characters");
            return res.redirect("/register");
        } else if (password.length < 8) {
            globalMessage.setMessage("danger", "Password invalid", "Make sure the password length is more or equal to 8 characters");
            return res.redirect("/register");
        } else {
            if (password !== password_confirmation) {
                globalMessage.setMessage("danger", "Password doesn't match", "Make sure the password confirmation matches the password");
                res.redirect("/register");
            }
            bcrypt.hash(password, saltRounds, async (err, hash) => {
                if (err) {
                    console.log(err);
                    res.redirect("/");
                } else {
                    const fileUrl = `${req.protocol}://${req.get('host')}/images/default2201.png`;
                    const result = await req.db.query("INSERT INTO users (username, password_hash, profile_image_url) VALUES ($1, $2, $3) RETURNING *", [username, hash, fileUrl]);
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

server.listen(process.env.PORT, '0.0.0.0', () => {
    console.log(`Server listening on port ${process.env.PORT}.`)
})

// app.listen(process.env.PORT, '0.0.0.0', () => {
//     console.log(`Listening on port ${process.env.PORT}.`);
// })
