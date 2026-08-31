const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const path = require("path");

const app = express();
const PORT = 3000;

const db = new sqlite3.Database(
    path.join(__dirname, "..", "database.db")
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "..", "public")));

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

    // Extended profile details for each user. One row per user,
    // created/updated the first time they fill in the "complete your
    // profile" form on the dashboard.
    db.run(`
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY,
            full_name TEXT,
            education TEXT,
            location TEXT,
            gender TEXT,
            age INTEGER,
            phone TEXT,
            bio TEXT,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    `);

    // Static catalog of courses the user can register for. Seeded once
    // below with some starter tech courses; feel free to add more rows.
    db.run(`
        CREATE TABLE IF NOT EXISTS courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT UNIQUE NOT NULL,
            category TEXT,
            description TEXT
        )
    `);

    // Which courses a user has registered for, and their progress.
    db.run(`
        CREATE TABLE IF NOT EXISTS user_courses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'in_progress',
            registered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            completed_at DATETIME,
            UNIQUE(user_id, course_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (course_id) REFERENCES courses(id)
        )
    `);

    // Issued certificates. Each row has a unique, publicly-checkable
    // certificate_code so anyone can cross-check authenticity later
    // via GET /api/certificates/verify/:code — without needing to log in.
    db.run(`
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate_code TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            course_id INTEGER NOT NULL,
            issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (course_id) REFERENCES courses(id)
        )
    `);

    const starterCourses = [
        ["Python Programming", "Programming", "Core Python syntax, data structures, and scripting."],
        ["JavaScript Essentials", "Programming", "Modern JS fundamentals, DOM, and async programming."],
        ["Web Development (HTML/CSS/JS)", "Web Development", "Build responsive websites from scratch."],
        ["Full Stack Web Development", "Web Development", "Frontend + backend + databases, end to end."],
        ["React.js", "Web Development", "Component-based UI development with React."],
        ["Node.js & Express", "Backend", "Build REST APIs and backend services with Node."],
        ["SQL & Databases", "Data", "Relational database design and SQL querying."],
        ["Data Structures & Algorithms", "Computer Science", "Core CS fundamentals for problem solving."],
        ["Software Engineering Basics", "Software", "Version control, SDLC, and team workflows."],
        ["Cloud Computing Basics", "Cloud", "Intro to cloud platforms and deployment."]
    ];

    const insertCourse = db.prepare(
        "INSERT OR IGNORE INTO courses (title, category, description) VALUES (?, ?, ?)"
    );
    starterCourses.forEach((course) => insertCourse.run(course));
    insertCourse.finalize();
});

function createToken() {
    return crypto.randomBytes(32).toString("hex");
}

function createCertificateCode() {
    // e.g. CERT-A1B2C3D4E5F6 — short, unique, easy to share/print.
    return "CERT-" + crypto.randomBytes(6).toString("hex").toUpperCase();
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


// Small helper: loads the logged-in user from the session cookie, or
// sends a 401 and stops the request. Keeps the routes below short.
async function requireAuth(req, res, next) {

    try {

        const token = req.cookies.session_token;

        if (!token) {
            return res.status(401).json({
                message: "No session found."
            });
        }

        const user = await getUserFromSession(token);

        if (!user) {
            return res.status(401).json({
                message: "Invalid session."
            });
        }

        req.user = user;
        next();

    } catch (error) {

        console.error(error);

        res.status(500).json({
            message: "Server error."
        });
    }
}


/* =========================================================
   PROFILE
   ========================================================= */

app.get("/api/profile", requireAuth, (req, res) => {

    db.get(
        "SELECT * FROM profiles WHERE user_id = ?",
        [req.user.id],
        (error, profile) => {

            if (error) {
                console.error(error);
                return res.status(500).json({ message: "Database error." });
            }

            res.json({
                profile: profile || null
            });
        }
    );
});


app.post("/api/profile", requireAuth, (req, res) => {

    const fullName = (req.body.full_name || "").trim();
    const education = (req.body.education || "").trim();
    const location = (req.body.location || "").trim();
    const gender = (req.body.gender || "").trim();
    const age = req.body.age ? parseInt(req.body.age, 10) : null;
    const phone = (req.body.phone || "").trim();
    const bio = (req.body.bio || "").trim();

    if (!fullName || !education || !location || !gender || !age) {
        return res.status(400).json({
            message: "Name, education, location, gender, and age are required."
        });
    }

    if (Number.isNaN(age) || age < 5 || age > 120) {
        return res.status(400).json({
            message: "Please enter a valid age."
        });
    }

    db.run(
        `
        INSERT INTO profiles (user_id, full_name, education, location, gender, age, phone, bio, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id) DO UPDATE SET
            full_name = excluded.full_name,
            education = excluded.education,
            location = excluded.location,
            gender = excluded.gender,
            age = excluded.age,
            phone = excluded.phone,
            bio = excluded.bio,
            updated_at = CURRENT_TIMESTAMP
        `,
        [req.user.id, fullName, education, location, gender, age, phone, bio],
        function (error) {

            if (error) {
                console.error(error);
                return res.status(500).json({ message: "Could not save profile." });
            }

            res.json({ message: "Profile saved successfully." });
        }
    );
});


/* =========================================================
   COURSES
   ========================================================= */

// Full catalog of courses available to register for.
app.get("/api/courses", requireAuth, (req, res) => {

    db.all("SELECT * FROM courses ORDER BY category, title", [], (error, rows) => {

        if (error) {
            console.error(error);
            return res.status(500).json({ message: "Database error." });
        }

        res.json({ courses: rows });
    });
});


// The logged-in user's registered courses, with status + certificate info.
app.get("/api/my-courses", requireAuth, (req, res) => {

    db.all(
        `
        SELECT
            user_courses.id AS registration_id,
            user_courses.status,
            user_courses.registered_at,
            user_courses.completed_at,
            courses.id AS course_id,
            courses.title,
            courses.category,
            courses.description,
            certificates.certificate_code
        FROM user_courses
        JOIN courses ON courses.id = user_courses.course_id
        LEFT JOIN certificates ON certificates.user_id = user_courses.user_id
            AND certificates.course_id = user_courses.course_id
        WHERE user_courses.user_id = ?
        ORDER BY user_courses.registered_at DESC
        `,
        [req.user.id],
        (error, rows) => {

            if (error) {
                console.error(error);
                return res.status(500).json({ message: "Database error." });
            }

            res.json({ courses: rows });
        }
    );
});


app.post("/api/courses/register", requireAuth, (req, res) => {

    const courseId = parseInt(req.body.course_id, 10);

    if (!courseId) {
        return res.status(400).json({ message: "A course must be selected." });
    }

    db.run(
        `
        INSERT INTO user_courses (user_id, course_id, status)
        VALUES (?, ?, 'in_progress')
        `,
        [req.user.id, courseId],
        function (error) {

            if (error) {

                if (error.message && error.message.includes("UNIQUE")) {
                    return res.status(409).json({
                        message: "You're already registered for this course."
                    });
                }

                console.error(error);
                return res.status(500).json({ message: "Could not register for course." });
            }

            res.status(201).json({ message: "Registered for course." });
        }
    );
});


// Demo/self-report completion toggle. In a real system this would be
// set automatically once course content/assessments are finished.
app.post("/api/courses/complete", requireAuth, (req, res) => {

    const courseId = parseInt(req.body.course_id, 10);

    if (!courseId) {
        return res.status(400).json({ message: "A course must be selected." });
    }

    db.run(
        `
        UPDATE user_courses
        SET status = 'completed', completed_at = CURRENT_TIMESTAMP
        WHERE user_id = ? AND course_id = ?
        `,
        [req.user.id, courseId],
        function (error) {

            if (error) {
                console.error(error);
                return res.status(500).json({ message: "Could not update course." });
            }

            if (this.changes === 0) {
                return res.status(404).json({ message: "Course registration not found." });
            }

            res.json({ message: "Course marked as completed." });
        }
    );
});


/* =========================================================
   CERTIFICATES
   ========================================================= */

// Generates a certificate for a completed course. Only allowed once
// per user/course — calling it again just returns the existing one.
app.post("/api/certificates/generate", requireAuth, (req, res) => {

    const courseId = parseInt(req.body.course_id, 10);

    if (!courseId) {
        return res.status(400).json({ message: "A course must be selected." });
    }

    db.get(
        "SELECT * FROM user_courses WHERE user_id = ? AND course_id = ?",
        [req.user.id, courseId],
        (error, registration) => {

            if (error) {
                console.error(error);
                return res.status(500).json({ message: "Database error." });
            }

            if (!registration || registration.status !== "completed") {
                return res.status(400).json({
                    message: "Course must be completed before generating a certificate."
                });
            }

            db.get(
                "SELECT * FROM certificates WHERE user_id = ? AND course_id = ?",
                [req.user.id, courseId],
                (error, existing) => {

                    if (error) {
                        console.error(error);
                        return res.status(500).json({ message: "Database error." });
                    }

                    if (existing) {
                        return res.json({
                            message: "Certificate already generated.",
                            certificate: existing
                        });
                    }

                    const code = createCertificateCode();

                    db.run(
                        `
                        INSERT INTO certificates (certificate_code, user_id, course_id)
                        VALUES (?, ?, ?)
                        `,
                        [code, req.user.id, courseId],
                        function (error) {

                            if (error) {
                                console.error(error);
                                return res.status(500).json({ message: "Could not generate certificate." });
                            }

                            res.status(201).json({
                                message: "Certificate generated.",
                                certificate: {
                                    id: this.lastID,
                                    certificate_code: code,
                                    user_id: req.user.id,
                                    course_id: courseId
                                }
                            });
                        }
                    );
                }
            );
        }
    );
});


// Public verification endpoint — no login required. Anyone holding a
// certificate ID can cross-check it's real and see who/what it's for.
app.get("/api/certificates/verify/:code", (req, res) => {

    const code = req.params.code.trim();

    db.get(
        `
        SELECT
            certificates.certificate_code,
            certificates.issued_at,
            users.username,
            profiles.full_name,
            courses.title AS course_title
        FROM certificates
        JOIN users ON users.id = certificates.user_id
        JOIN courses ON courses.id = certificates.course_id
        LEFT JOIN profiles ON profiles.user_id = certificates.user_id
        WHERE certificates.certificate_code = ?
        `,
        [code],
        (error, row) => {

            if (error) {
                console.error(error);
                return res.status(500).json({ message: "Database error." });
            }

            if (!row) {
                return res.status(404).json({
                    valid: false,
                    message: "No certificate found with that ID."
                });
            }

            res.json({
                valid: true,
                certificate: row
            });
        }
    );
});


app.get("/dashboard", (req, res) => {

    res.sendFile(
        path.join(__dirname, "..", "public", "dashboard.html")
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
