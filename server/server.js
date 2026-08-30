const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const path = require("path");

const app = express();
const PORT = 3000;

const db = new sqlite3.Database("./database.db");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
});

function createToken() {
    return crypto.randomBytes(32).toString("hex");
}

function getUser(username) {
    return new Promise((resolve, reject) => {
        db.get(
            "SELECT * FROM users WHERE username = ?",
            [username],
            (error, row) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(row);
                }
            }
        );
    });
}

function getUserFromSession(token) {
    return new Promise((resolve, reject) => {
        db.get(
            `
            SELECT users.id, users.username
            FROM users
            JOIN sessions
            ON users.id = sessions.user_id
            WHERE sessions.token = ?
            `,
            [token],
            (error, row) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(row);
                }
            }
        );
    });
}


app.post("/api/register", async (req, res) => {

    try {

        const username = req.body.username?.trim();
        const password = req.body.password;

        if (!username || !password) {
            return res.status(400).json({
                message: "Username and password are required."
            });
        }

        if (username.length < 3) {
            return res.status(400).json({
                message: "Username must contain at least 3 characters."
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                message: "Password must contain at least 6 characters."
            });
        }

        const existingUser = await getUser(username);

        if (existingUser) {
            return res.status(409).json({
                message: "Username already exists."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        db.run(
            `
            INSERT INTO users (username, password)
            VALUES (?, ?)
            `,
            [username, hashedPassword],
            function(error) {

                if (error) {
                    console.error(error);

                    return res.status(500).json({
                        message: "Registration failed."
                    });
                }

                res.status(201).json({
                    message: "Account created successfully."
                });
            }
        );

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message: "Server error."
        });
    }
});


app.post("/api/login", async (req, res) => {

    try {

        const username = req.body.username?.trim();
        const password = req.body.password;

        if (!username || !password) {
            return res.status(400).json({
                message: "Username and password are required."
            });
        }

        const user = await getUser(username);

        if (!user) {
            return res.status(401).json({
                message: "Invalid username or password."
            });
        }

        const passwordCorrect = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordCorrect) {
            return res.status(401).json({
                message: "Invalid username or password."
            });
        }

        db.get(
            "SELECT * FROM sessions WHERE user_id = ?",
            [user.id],
            (error, session) => {

                if (error) {
                    console.error(error);

                    return res.status(500).json({
                        message: "Database error."
                    });
                }

                if (session) {
                    return res.status(409).json({
                        message: "This account is already logged in."
                    });
                }

                const token = createToken();

                db.run(
                    `
                    INSERT INTO sessions (user_id, token)
                    VALUES (?, ?)
                    `,
                    [user.id, token],
                    function(error) {

                        if (error) {
                            console.error(error);

                            return res.status(500).json({
                                message: "Session could not be created."
                            });
                        }

                        console.log("SESSION CREATED");
                        console.log("Username:", user.username);
                        console.log("Token:", token);

                        res.cookie("session_token", token, {
                            httpOnly: true,
                            sameSite: "lax",
                            secure: false,
                            maxAge: 2 * 60 * 60 * 1000,
                            path: "/"
                        });

                        res.status(200).json({
                            message: "Login successful.",
                            username: user.username
                        });
                    }
                );
            }
        );

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message: "Server error."
        });
    }
});


app.get("/api/me", async (req, res) => {

    try {

        const token = req.cookies.session_token;

        console.log("COOKIE:", token);

        if (!token) {
            return res.status(401).json({
                message: "No session found."
            });
        }

        const user = await getUserFromSession(token);

        console.log("SESSION USER:", user);

        if (!user) {
            return res.status(401).json({
                message: "Invalid session."
            });
        }

        res.json({
            loggedIn: true,
            username: user.username
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message: "Server error."
        });
    }
});


app.post("/api/logout", (req, res) => {

    const token = req.cookies.session_token;

    if (!token) {
        return res.json({
            message: "Already logged out."
        });
    }

    db.run(
        "DELETE FROM sessions WHERE token = ?",
        [token],
        (error) => {

            if (error) {
                console.error(error);

                return res.status(500).json({
                    message: "Logout failed."
                });
            }

            res.clearCookie("session_token", {
                httpOnly: true,
                sameSite: "lax",
                secure: false,
                path: "/"
            });

            res.json({
                message: "Logged out successfully."
            });
        }
    );
});


app.get("/dashboard", (req, res) => {

    res.sendFile(
        path.join(__dirname, "public", "dashboard.html")
    );
});


app.listen(PORT, () => {

    console.log("");
    console.log("================================");
    console.log(" TechZone Server Started");
    console.log("================================");
    console.log(` http://localhost:${PORT}`);
    console.log("");

});