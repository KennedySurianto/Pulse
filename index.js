import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import pg from "pg";

dotenv.config();

// const db = new pg.Client({
//     user: process.env.DB_USER,
//     host: process.env.DB_HOST,
//     password: process.env.DB_PASS,
//     port: process.env.DB_PORT
// })
// db.connect();

const app = express();
const port = 3000;

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/", (req, res) => {
    res.render("home.ejs");
})

app.get("/home", (req, res) => {
    res.render("user_home.ejs");
})

app.get("/login", (req, res) => {
    res.render("login.ejs");
})

app.get("/register", (req, res) => {
    res.render("register.ejs");
})

app.listen(port, () => {
    console.log(`Listening on port ${port}.`);
})