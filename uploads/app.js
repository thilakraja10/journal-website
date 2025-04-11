const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const path = require('path'); // ✅ Import the 'path' module
const jwt = require("jsonwebtoken");
const multer = require("multer");
const cors = require("cors");
const fs = require("fs");
const nodemailer = require('nodemailer');
const session = require("express-session");
const crypto = require("crypto"); // For generating unique Login ID
const bcrypt = require("bcrypt"); // For password hashing
const { rootCertificates } = require("tls");
const { v4: uuidv4 } = require("uuid");
const PDFDocument = require('pdfkit');
require('pdfkit-table'); //
const createTable = require('pdfkit-table'); 
const PdfPrinter = require('pdfmake');
const pdf = require('html-pdf');
require("dotenv").config();
require("dotenv").config();
// const SECRET_KEY = process.env.SECRET_KEY;
const SECRET_KEY = "your_secret_key";
const app = express();
app.use(cors());
app.use(bodyParser.json());
app.set("view engine", "ejs");
const cookieParser = require("cookie-parser");
const { name } = require("ejs");
const { log } = require("console");
app.use(express.urlencoded({ extended: true }));
app.use(cors({ origin: "http://localhost:3001", credentials: true }));
app.use(cookieParser());
// ✅ Set views directory (if your EJS files are in a 'views' folder)
app.set("views", path.join(__dirname, "views"));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
// ✅ Middleware for parsing request body
app.use(express.urlencoded({ extended: true }));
app.use(express.json());


// Ensure subfolders exist
const uploadDir = 'uploads/payment';

if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Multer storage configuration


// File filter for type-specific validation
const fileFilter = (req, file, cb) => {
    const allowedFileTypes = ['.jpg', '.jpeg', '.png', '.pdf'];
    const fileExt = path.extname(file.originalname).toLowerCase();

    if (allowedFileTypes.includes(fileExt)) {
        cb(null, true); // Accept the file
    } else {
        cb(new Error("Invalid file type. Only JPG, JPEG, PNG, and PDF are allowed."), false); // Reject the file
    }
};

// Multer storage configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/payment'); // Ensure folder exists
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}${path.extname(file.originalname)}`);
    }
});

const uploadPath = 'uploads/research';
if (!fs.existsSync(uploadPath)) {
    fs.mkdirSync(uploadPath, { recursive: true });
}

// Correct multer storage configuration
const storage1 = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, uploadPath); // Correct folder path
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}${path.extname(file.originalname)}`);
    }
});

// File filter logic
const fileFilter1 = (req, file, cb) => {
    const allowedFileTypes = ['.pdf', '.docx', '.doc'];
    const fileExt = path.extname(file.originalname).toLowerCase();

    if (allowedFileTypes.includes(fileExt)) {
        cb(null, true); // Accept the file
    } else {
        cb(new Error("Invalid file type. Only PDF, DOCX, and DOC are allowed."), false);
    }
};

// Correct multer configuration
const upload1 = multer({
    storage: storage1, // ✅ Correct key is `storage`, not `storages1`
    fileFilter: fileFilter1 // ✅ Correct key is `fileFilter`, not `fileFilter1`
});

const uploadDirs = ['uploads/conference'];
uploadDirs.forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
});

// Multer Configuration
const storage2 = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/conference'); // Correct folder path
    },
    filename: (req, file, cb) => {
        cb(null, `${Date.now()}${path.extname(file.originalname)}`);
    }
});

// File filter to allow only PDF, DOCX, and DOC
const fileFilter2 = (req, file, cb) => {
    const allowedFileTypes = ['.pdf', '.docx', '.doc'];
    const fileExt = path.extname(file.originalname).toLowerCase();

    if (allowedFileTypes.includes(fileExt)) {
        cb(null, true);
    } else {
        cb(new Error("Invalid file type. Only PDF, DOCX, and DOC are allowed."), false);
    }
};

const upload2 = multer({
    storage: storage2,
    fileFilter: fileFilter2
});
app.post('/upload', (req, res) => {
    console.log('Request Body:', req.body);  // ✅ Confirm 'type' is present
    upload.single('file')(req, res, (err) => {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        res.json({ file: req.file });
    });
});

const upload = multer({ storage, fileFilter });

// const upload2 = multer({ storages2, fileFilter });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files from 'uploads' folder
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Upload endpoint

app.post('/upload', upload.single('file'), (req, res) => {
    res.json({ file: req.file });
});


app.use('/papers', express.static(path.join(__dirname, 'uploads', 'latestfile')));

app.use("/latestfile", express.static(path.join(__dirname, "latestfile")));



// const db = mysql.createConnection({
//     host: process.env.DB_HOST,
//     user:'root',
//     password: 'MYsql@2025',
//     database:'research_portal'
// });

// db.connect(err => {
//     if (err) console.error("Database connection failed:", err);
//     else console.log("Connected to MySQL database!");
// });




const db = mysql.createConnection({
    host: '127.0.0.1', // MySQL server IP address
    user: 'root', // MySQL username
    password: 'MYsql@2025', // MySQL password
    database: 'research_portal' // Database name
  });
  db.connect(err => {
    if (err) console.error("Database connection failed:", err);
    else console.log("Connected to MySQL database!");
});
const loadHTML = (fileName) => {
    try {
        return fs.readFileSync(path.join(__dirname, 'public', fileName), 'utf-8');
    } catch (error) {
        console.error(`Error loading file: ${fileName}`, error);
        return `<p>Error loading content</p>`;
    }
};

app.get('/header', (req, res) => {
    res.send(loadHTML('header.html'));
});

app.get('/footer', (req, res) => {
    res.send(loadHTML('footer.html'));
});
app.get('/header1', (req, res) => {
    res.send(loadHTML('header1.html'));
});

app.get('/footer1', (req, res) => {
    res.send(loadHTML('footer1.html'));
});
// Route to serve main HTML file
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});
const useAlternativeHeader = process.env.USE_ALTERNATIVE_HEADER === 'true';

let headerPath = path.join(__dirname, 'public', 'header.html');
let footerPath = path.join(__dirname, 'public', 'footer.html');

if (useAlternativeHeader) {
    headerPath = path.join(__dirname, 'public', 'header1.html');
    footerPath = path.join(__dirname, 'public', 'footer1.html');

}


const headerHTML = fs.readFileSync(headerPath, 'utf8');
const footerHTML = fs.readFileSync(footerPath, 'utf8');

// Function to generate a unique Login ID
function generateLoginId1() {
    return "IJSRCAUTH" + crypto.randomInt(100000, 999999); // Example: ICACAUTH123456
}

// ✅ REGISTER AUTHOR
app.post("/register", async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    // Validate passwords match
    if (password !== confirmPassword) {
        return res.status(400).json({ success: false, message: "Passwords do not match!" });
    }

    try {
        // Check if email already exists
        const [existingUsers] = await db.promise().query("SELECT * FROM authors WHERE email = ?", [email]);
        if (existingUsers.length > 0) {
            return res.status(400).json({ success: false, message: "Email already registered!" });
        }

        // Generate unique Login ID
        let loginId;
        let loginIdExists;
        do {
            loginId = generateLoginId1();
            [loginIdExists] = await db.promise().query("SELECT * FROM authors WHERE loginId = ?", [loginId]);
        } while (loginIdExists.length > 0);

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new author
        await db.promise().query(
            "INSERT INTO authors (loginId, name, email, password) VALUES (?, ?, ?, ?)",
            [loginId, name, email, hashedPassword]
        );

        res.json({ success: true, message: "Registration successful!", loginId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});
app.use(express.json());

// ✅ Serve static files from "public" folder
app.use(express.static(path.join(__dirname, 'public')));

// ✅ Route to serve "home.html"
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'home.html'));
});
app.post("/login", (req, res) => {
    const { loginId, password } = req.body;

    // Find user in the database
    const sql = "SELECT * FROM authors WHERE loginId = ?";
    db.query(sql, [loginId], async (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Server error!" });

        if (result.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid login ID!" });
        }

        const user = result[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: "Invalid password!" });
        }

        // 🚨 Generate JWT WITHOUT SECRET KEY (Not Secure)
        const token = jwt.sign({ loginId: user.loginId }, null, { algorithm: "none" });

        res.json({ success: true, message: "Login successful!", token });
    });
});

// 🔄 Forgot Password (Dummy Response)
app.post("/forgot-password", (req, res) => {
    const { email } = req.body;

    // Query to get user details (you can replace this with your actual database query)
    const sql = "SELECT loginId, password FROM authors WHERE email = ?";
    db.query(sql, [email], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: "Server error!" });
        }

        if (result.length === 0) {
            return res.status(404).json({ success: false, message: "Email not found!" });
        }

        const user = result[0]; // Assuming only one result (email is unique)

        // Create a transporter with your email credentials (using environment variables)
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: "thilakraja10@gmail.com", // Replace with your email
                pass: "tdai putr abny luxc" 
            }
        });

        // Prepare the email options
        const mailOptions = {
            from: process.env.EMAIL_USER, // Use the email from the .env file
            to: email,
            subject: "Password Recovery",
            text: `Your login credentials:\n\nLogin ID: ${user.loginId}\nPassword: ${user.password}`
        };

        // Send the email
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                return res.status(500).json({ message: "Error sending email", success: false });
            }
            res.json({ message: "Password sent to your email", success: true });
        });
    });
});
async function generatePaperId1() {
    return new Promise((resolve, reject) => {
        db.query("SELECT paperId FROM manuscript ORDER BY submissionDate DESC LIMIT 1", (err, result) => {
            if (err) return reject(err);
            if (result.length === 0) return resolve("IJSRCP1");

            const lastIdMatch = result[0].paperId.match(/\d+/);
            const lastId = lastIdMatch ? parseInt(lastIdMatch[0]) : 0;
            const newPaperId = `IJSRCP${lastId + 1}`;

            // Double-check that the new paperId does not exist
            db.query("SELECT paperId FROM manuscript WHERE paperId = ?", [newPaperId], (err, existing) => {
                if (err) return reject(err);
                if (existing.length > 0) {
                    // If `newPaperId` already exists, increase by 1 and retry
                    resolve(`IJSRCP${lastId + 2}`);
                } else {
                    resolve(newPaperId);
                }
            });
        });
    });
}

// 🔹 API Route: Submit Manuscript
// app.post("/submit", upload1.single("file"), async (req, res) => {
//     try {
//         console.log("🟢 Request Body:", req.body);
//         console.log("🟡 Uploaded File:", req.file);

//         const { title, authors, email, abstract, keywords, comments, loginId } = req.body;
//         const fileUrl = req.file ? `uploads/research/${req.file.filename}` : null;

//         if (!title || !authors || !email || !abstract || !keywords || !loginId) {
//             return res.status(400).json({ message: "All fields are required!" });
//         }

//         if (!req.file) {
//             return res.status(400).json({ message: "File upload failed!" });
//         }

//         const paperId = await generatePaperId1();

//         const sql = `
//             INSERT INTO manuscript (id, paperId, title, authors, email, abstract, keywords, fileUrl, comments, reviewer, status, submissionDate, loginId)
//             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?)
//         `;

//         db.query(sql, [uuidv4(), paperId, title, authors, email, abstract, keywords, fileUrl, comments || "No comments", "None", "submitted", loginId], (err) => {
//             if (err) {
//                 console.error("🔥 MySQL Error:", err);
//                 return res.status(500).json({ success: false, message: "Error submitting manuscript.", error: err.sqlMessage });
//             }
//             res.json({ success: true, message: "✅ Manuscript submitted successfully!", redirectURL: `/author_dashboard/${loginId}` });
//         });

//     } catch (error) {
//         console.error("❌ Submission Error:", error);
//         res.status(500).json({ message: "Internal Server Error" });
//     }
// });
app.post("/submit", upload1.single("file"), async (req, res) => {
    try {
        console.log("🟢 Request Body:", req.body);
        console.log("🟡 Uploaded File:", req.file);

        const { title, authors, email, abstract, keywords, comments, loginId } = req.body;
        const fileUrl = req.file ? `uploads/research/${req.file.filename}` : null;

        if (!title || !authors || !email || !abstract || !keywords || !loginId) {
            return res.status(400).json({ message: "All fields are required!" });
        }

        if (!req.file) {
            return res.status(400).json({ message: "File upload failed!" });
        }

        const paperId = await generatePaperId1();
        const uniqueId = uuidv4();

        const sql = `
            INSERT INTO manuscript (id, paperId, title, authors, email, abstract, keywords, fileUrl, comments, reviewer, status, submissionDate, loginId)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?)
        `;

        db.query(sql, [
            uniqueId, paperId, title, authors, email, abstract, keywords,
            fileUrl, comments || "No comments", "None", "submitted", loginId
        ], async (err) => {
            if (err) {
                console.error("🔥 MySQL Error:", err);
                return res.status(500).json({ success: false, message: "Error submitting manuscript.", error: err.sqlMessage });
            }

            // ✅ Send email after successful DB insert
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: 'thilakraja10@gmail.com',       // 🔁 Replace with your Gmail
                    pass: 'tunw uvnn dujq khds'           // 🔁 Replace with your Gmail App Password
                }
            });

            const mailOptions = {
                from: 'your-email@gmail.com',
                to: email,
                subject: 'Research Manuscript Submission Confirmation - IJSRC',
                html: `
                    <h3>Dear Author,</h3>
                    <p>Thank you for submitting your research manuscript to IJSRC.</p>
                    <p><strong>Paper ID:</strong> ${paperId}</p>
                    <p><strong>Title:</strong> ${title}</p>
                    <p>Your submission has been received and is currently under review.</p>
                    <br/>
                    <p>Best regards,<br/>IJSRC Team</p>
                `
            };

            try {
                await transporter.sendMail(mailOptions);
                console.log("📧 Confirmation email sent to:", email);
            } catch (emailErr) {
                console.error("❌ Error sending email:", emailErr);
            }

            res.json({ success: true, message: "✅ Manuscript submitted successfully!", redirectURL: `/author_dashboard/${loginId}` });
        });

    } catch (error) {
        console.error("❌ Submission Error:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});
// 🔹 API Route: Get Author Dashboard
app.get("/author_dashboard/:loginId", (req, res) => {
    const loginId = req.params.loginId.toLowerCase();

    db.query("SELECT * FROM authors WHERE loginId = ?", [loginId], (err, authorResult) => {
        if (err || authorResult.length === 0) {
            return res.status(404).send("❌ Author not found.");
        }

        const author = authorResult[0];

        db.query("SELECT * FROM manuscript WHERE loginId = ?", [loginId], (err, manuscriptResults) => {
            if (err) {
                console.error("🔥 Error fetching manuscripts:", err);
                return res.status(500).send("Error fetching manuscripts");
            }

            res.render("author_dashboard", {
                author,
                manuscripts: manuscriptResults
            });
        });
    });
});

// 🔹 API Route: Get All Manuscripts
app.get("/manuscripts", (req, res) => {
    db.query("SELECT * FROM manuscript", (err, manuscripts) => {
        if (err) {
            console.error("❌ Fetch Error:", err);
            return res.status(500).json({ message: "Internal Server Error" });
        }
        res.json(manuscripts);
    });
});

// 🔹 API Route: Update Manuscript Status
app.put("/update-status/:paperId", (req, res) => {
    const { paperId } = req.params;
    const { status } = req.body;

    db.query("UPDATE manuscript SET status = ? WHERE paperId = ?", [status, paperId], (err, result) => {
        if (err) {
            console.error("❌ Update Error:", err);
            return res.status(500).json({ message: "Internal Server Error" });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "❌ Manuscript not found!" });
        }
        res.json({ message: "✅ Status updated successfully!" });
    });
});

// 🔹 API Route: View Manuscript by Paper ID
app.get("/submission/:paperId", (req, res) => {
    const { paperId } = req.params;

    db.query("SELECT * FROM manuscript WHERE paperId = ?", [paperId], (err, result) => {
        if (err) {
            console.error("❌ Fetch Error:", err);
            return res.status(500).send("Server Error");
        }
        if (result.length === 0) {
            return res.status(404).send("❌ Manuscript not found");
        }
        res.render("submission_details", { paper: result[0] });
    });
});
app.get("/get-papers", (req, res) => {
    const sql = "SELECT paperId, title, authors, email, submissionDate, reviewer FROM manuscript ORDER BY CAST(SUBSTRING(paperId, 7) AS UNSIGNED) ASC "; 

    db.query(sql, (err, results) => {
        if (err) {
            console.error("Error fetching papers:", err);
            return res.status(500).json({ error: "Error fetching papers" });
        }
        res.json(results);
    });
});


// API to fetch all reviewers
app.get("/get-reviewers", (req, res) => {
    const sql = "SELECT * FROM reviewers";
    db.query(sql, (err, results) => {
        if (err) {
            res.status(500).json({ error: "Database error" });
        } else {
            res.json(results);
        }
    });
});

// API to assign a reviewer to a paper

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: "thilakraja10@gmail.com", // Replace with your email
        pass: "tdai putr abny luxc" 
    }
});

// Add Reviewer Route
app.post("/add-reviewer", (req, res) => {
    const { name, affiliation, email, profile, researchArea } = req.body;

    if (!name || !email) {
        return res.status(400).json({ message: "Name and Email are required" });
    }

    const sql = `INSERT INTO reviewers (name, affiliation, email, profile, researchArea) VALUES (?, ?, ?, ?, ?)`;
    console.log("Received reviewer ID for deletion:", researchArea);

    db.query(sql, [name, affiliation, email, profile || "N/A", researchArea ], (err, result) => {
        if (err) {
            console.error("Error adding reviewer:", err);
            return res.status(500).json({ message: "Error adding reviewer", error: err.sqlMessage });
        }

        // Send email notification
        const mailOptions = {
            from: 'your-email@gmail.com',       // Replace with your email
            to: email,                          // Reviewer email
            subject: 'Reviewer Added Successfully',
            text: `Hello ${name},\n\nYou have been successfully added as a reviewer to our system.\n\nThank you,\nThe Team`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending email:", error);
                return res.status(500).json({ message: "Reviewer added, but email could not be sent", error: error.message });
            }
            console.log("Email sent: " + info.response);
            res.status(201).json({ message: "Reviewer added successfully and email sent!" });
        });
    });
});


// ✅ Get Reviewers
app.delete("/delete-reviewer/:id", (req, res) => {
    const reviewerId = req.params.id;
    console.log("Received reviewer ID for deletion:", reviewerId);

    if (!reviewerId || isNaN(reviewerId)) {
        return res.status(400).json({ message: "Invalid reviewer ID" });
    }

    const sql = "DELETE FROM reviewers WHERE id = ?";
    db.query(sql, [reviewerId], (err, result) => {
        if (err) {
            console.error("Error deleting reviewer:", err);
            return res.status(500).json({ message: "Database error" });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Reviewer not found!" });
        }

        res.json({ message: "Reviewer deleted successfully!" });
    });
});



// const nodemailer = require('nodemailer');

// app.post('/assign-reviewer', async (req, res) => {
//     // Log the incoming request body to check paperId and reviewerId
//     console.log('Request Body:', req.body);

//     const { paperId, reviewerId, reviewerName } = req.body;
// const status = "Under Review";
//     // Validate the incoming data
//     if (!paperId || !reviewerId || !reviewerName) {
//         return res.status(400).json({ message: 'Missing paperId, reviewerId, or reviewerName' });
//     }

//     console.log('Assigning reviewer:', { paperId, reviewerId, reviewerName });

//     try {
//         // SQL query to update the paper with the reviewer name
//         const updateQuery = 'UPDATE manuscript SET reviewer = ?,status=? WHERE paperId = ?';
//         await db.promise().query(updateQuery, [reviewerName,status, paperId]);

//         // Optionally, get reviewer details (like name or email) from the `reviewers` table
//         const getReviewerQuery = 'SELECT name, email FROM reviewers WHERE name = ?';
//         const [reviewerData] = await db.promise().query(getReviewerQuery, [reviewerName]);

//         if (reviewerData.length === 0) {
//             return res.status(404).json({ message: 'Reviewer not found' });
//         }

//         const reviewerNameFromDb = reviewerData[0]?.name || 'Unknown Reviewer';
//         const reviewerEmail = reviewerData[0]?.email;

//         // Ensure the email is correct before proceeding
//         if (!reviewerEmail) {
//             return res.status(400).json({ message: 'Reviewer email is missing' });
//         }

//         console.log('Reviewer email:', reviewerEmail); // Debugging line

//         // Configure Nodemailer
//         let transporter = nodemailer.createTransport({
//             service: 'gmail', // You can use other services like Outlook, SendGrid, etc.
//             auth: {
//                 user: "thilakraja10@gmail.com", // Replace with your email
//                 pass: "tdai putr abny luxc" // App password (if 2FA is enabled)
//             }
//         });

//         // Set up email data
//         let mailOptions = {
//             from: 'your-email@gmail.com',
//             to: reviewerEmail,
//             subject: 'New Paper Review Assignment',
//             text: `Dear ${reviewerNameFromDb},\n\nYou have been assigned to review the paper with Paper ID: ${paperId}.\n\nBest regards,\nYour Paper Management Team`
//         };

//         // Send email
//         transporter.sendMail(mailOptions, (error, info) => {
//             if (error) {
//                 console.log('Error sending email:', error);
//                 return res.status(500).json({ message: 'Error sending email', error: error.message });
//             }

//             console.log('Email sent: ' + info.response); // This logs the Gmail SMTP response

//             // Check if email was actually delivered
//             if (info.accepted && info.accepted.length > 0) {
//                 console.log('Email successfully sent to:', info.accepted);
//             } else {
//                 console.error('Email was not accepted by Gmail SMTP server.');
//             }
//         });

//         // Respond with success message
//         res.status(200).json({
//             message: 'Reviewer assigned successfully!',
//             reviewerName: reviewerNameFromDb
//         });
//     } catch (err) {
//         console.error('Error assigning reviewer:', err);
//         res.status(500).json({ message: 'Error assigning reviewer', error: err.message });
//     }
// });
app.post('/assign-reviewer', async (req, res) => {
    console.log('Request Body:', req.body);

    const { paperId, reviewerId, reviewerName } = req.body;
    const status = "Under Review";

    if (!paperId || !reviewerId || !reviewerName) {
        return res.status(400).json({ message: 'Missing paperId, reviewerId, or reviewerName' });
    }

    console.log('Assigning reviewer:', { paperId, reviewerId, reviewerName });

    try {
        // 1. Update manuscript with reviewer and status
        const updateQuery = 'UPDATE manuscript SET reviewer = ?, status = ? WHERE paperId = ?';
        await db.promise().query(updateQuery, [reviewerName, status, paperId]);

        // 2. Get reviewer info
        const [reviewerData] = await db.promise().query('SELECT name, email FROM reviewers WHERE name = ?', [reviewerName]);
        if (reviewerData.length === 0) {
            return res.status(404).json({ message: 'Reviewer not found' });
        }
        const reviewerNameFromDb = reviewerData[0].name;
        const reviewerEmail = reviewerData[0].email;

        // 3. Get author info
        const [authorData] = await db.promise().query('SELECT title, email FROM manuscript WHERE paperId = ?', [paperId]);
        if (authorData.length === 0) {
            return res.status(404).json({ message: 'Author not found for this paperId' });
        }
        const paperTitle = authorData[0].title;
        const authorEmail = authorData[0].email;

        // 4. Setup mail transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'thilakraja10@gmail.com', // Your Gmail
                pass: 'tdai putr abny luxc'      // App Password
            }
        });

        // 5. Mail to Reviewer
        const reviewerMailOptions = {
            from: 'your-email@gmail.com',
            to: reviewerEmail,
            subject: 'New Paper Review Assignment',
            text: `Dear ${reviewerNameFromDb},\n\nYou have been assigned to review the paper titled: "${paperTitle}" (Paper ID: ${paperId}).\n\nPlease log in to your dashboard to review the paper.\n\nBest regards,\nIJSRC Editorial Team`
        };

        // 6. Mail to Author
        const authorMailOptions = {
            from: 'your-email@gmail.com',
            to: authorEmail,
            subject: 'Your Paper is Under Review - IJSRC',
            text: `Dear Author,\n\nYour manuscript titled "${paperTitle}" (Paper ID: ${paperId}) has been assigned to a reviewer and is now under review.\n\nWe will notify you once the review process is complete.\n\nThank you for your submission.\n\nBest regards,\nIJSRC Editorial Team`
        };

        // 7. Send emails
        await transporter.sendMail(reviewerMailOptions);
        console.log("✅ Reviewer email sent to:", reviewerEmail);

        await transporter.sendMail(authorMailOptions);
        console.log("✅ Author email sent to:", authorEmail);

        res.status(200).json({
            message: 'Reviewer assigned and emails sent successfully!',
            reviewerName: reviewerNameFromDb
        });

    } catch (err) {
        console.error('❌ Error assigning reviewer:', err);
        res.status(500).json({ message: 'Error assigning reviewer', error: err.message });
    }
});

app.post('/reviewer5-register', async (req, res) => {
    const { name, email, password } = req.body;

    // Check if all required fields are provided
    if (!name || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into the reviewerlo table
    const query = 'INSERT INTO reviewerlo (name, email, password) VALUES (?, ?, ?)';
    db.query(query, [name, email, hashedPassword], (err, result) => {
        if (err) {
            console.error('Error inserting user:', err);
            return res.status(500).json({ message: 'Internal server error.' });
        }
        res.status(201).json({ message: 'User registered successfully!' });
    });
});

// User Login Endpoint
app.post('/reviewer5-login', (req, res) => {
    const { email, password } = req.body;

    // Check if both fields are provided
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    // Find the user by email
    const query = 'SELECT * FROM reviewerlo WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ message: 'Internal server error.' });
        }
        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        // Compare the password
        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        // const token = jwt.sign({ id: user.id, role: user.name }, "secretkey", { expiresIn: "1h" });

        // Generate a token
        // const token = jwt.sign({ loginId: user.loginId }, null, { algorithm: "none" });
        const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, SECRET_KEY, { expiresIn: "1h" });

        res.json({ message: "Login successful", reviewer: { name: user.name, email: user.email }, token });
        // res.status(200).json({
        //     message: 'Login successful!',
        //     token: token
        // });
    });
});
app.use("/files", express.static(path.join(__dirname, "latestfile")));
const folders = [
    "vol_1_issue_1_2019",
    "vol_1_issue_2_2019",
    "vol_2_issue_1_2020",
    "vol_2_issue_2_2020",
    "vol_3_issue_1_2021",
    "vol_3_issue_2_2021",
    "vol_4_issue_1_2022",
    "vol_4_issue_2_2022",
    "vol_5_issue_1_2023",
    "vol_5_issue_2_2023",
    "vol_6_issue_1_2024",
    "vol_6_issue_2_2024",
    "vol_7_issue_1_2025"
];

// Form Submission Endpoint
app.post("/submit-form", async (req, res) => {
    try {
        const { name, email, phone, message, pdfFile } = req.body;

        // Validate form fields
        if (!name || !email || !phone || !message || !pdfFile) {
            return res.json({ success: false, message: "All fields are required" });
        }

        // Save form data in MySQL
        const query = `INSERT INTO form_submissions (name, email, phone, message, pdfFile) VALUES (?, ?, ?, ?, ?)`;
        db.query(query, [name, email, phone, message, pdfFile], (err, result) => {
            if (err) {
                console.error("Error inserting data:", err);
                return res.status(500).json({ success: false, message: "Server Error" });
            }

            // Find the correct folder containing the PDF
            let foundFolder = null;

            for (const folder of folders) {
                const filePath = path.resolve(__dirname, `../latestfile/${folder}/${pdfFile}`);
                console.log("Checking file path:", filePath);  // Log the file path for debugging
                if (fs.existsSync(filePath)) {
                    foundFolder = folder;
                    break;
                }
            }

            if (foundFolder) {
                res.json({ success: true, folder: foundFolder, pdfFile });
            } else {
                res.json({ success: false, message: "PDF file not found." });
            }
        });
    } catch (error) {
        console.error("Server Error:", error);
        res.status(500).json({ success: false, message: "Server Error" });
    }
});


// Assuming you use express-session
// app.get("/assigned-papers", async (req, res) => {
//     try {
//         let token = req.cookies.token || (req.headers.authorization && req.headers.authorization.split(" ")[1]);
//         // const reviewerName = req.query.reviewerName; // Get reviewer name from query parameters

//         // if (!reviewerName) {
//         //     return res.status(400).json({ message: "Reviewer name is required" });
//         // }
//          const decoded = jwt.verify(token, process.env.JWT_SECRET || "default_secret");
        
//          console.log("Decoded Token:", decoded.name); 

//         // console.log("Fetching assigned papers for:", reviewerName); // Debugging

//         // Fetch assigned papers from the database
//         const [assignedPapers] = await db.query(
//             "SELECT * FROM manuscript WHERE reviewer = ?", 
//             [decoded.name]
//         );

//         if (assignedPapers.length === 0) {
//             return res.status(404).json({ message: "No assigned papers found for this reviewer" });
//         }

//         console.log("Assigned Papers:", assignedPapers); // Debugging

//         res.status(200).json({ papers: assignedPapers });

//     } catch (error) {
//         console.error("Error fetching assigned papers:", error);
//         res.status(500).json({ message: "Error fetching assigned papers", error: error.message });
//     }
// });

app.get("/assigned-papers", (req, res) => {
    const reviewerName = req.query.name; // Fetch from query parameter

    if (!reviewerName) {
        return res.status(400).json({ message: "Reviewer name is required" });
    }

    const query = "SELECT * FROM manuscript WHERE reviewer = ?";
    db.query(query, [reviewerName], (err, results) => {
        if (err) {
            return res.status(500).json({ message: "Database error", error: err });
        }

        if (results.length === 0) {
            return res.json({ message: "No papers assigned", papers: [] });
        }

        res.json({ reviewerName, papers: results });
    });
});


app.post("/save-comments", (req, res) => {
    const { papers } = req.body;

    if (!papers || papers.length === 0) {
        return res.status(400).json({ message: "No data provided" });
    }

    let updateQueries = papers.map(paper => {
        return new Promise((resolve, reject) => {
            const query = "UPDATE manuscript SET status = ?, comments = ? WHERE title = ?";
            db.query(query, [paper.status, paper.comments, paper.title], (err, result) => {
                if (err) reject(err);
                else resolve(result);
            });
        });
    });

    Promise.all(updateQueries)
        .then(() => res.json({ message: "Data saved successfully" }))
        .catch(err => res.status(500).json({ message: "Error saving data", error: err }));
});


app.get("/api/reviewer-comments", (req, res) => {
    const query = "SELECT paperId, title AS paperTitle, reviewer AS reviewerName, comments, status FROM manuscript ORDER BY CAST(SUBSTRING(paperId, 7) AS UNSIGNED) ASC ";

    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: "Error fetching reviewer comments", details: err });
        }

        // Format response to match previous MongoDB structure
        res.json(results.map(paper => ({
            _id: paper.paperId,
            paperTitle: paper.paperTitle,
            reviewerName: paper.reviewerName,
            comments: paper.comments || "No comments",
            status: paper.status
        })));
    });
});

// Start server
const PORT = process.env.PORT || 3001;

// Allow the server to listen on all network interfaces (0.0.0.0)
// app.listen(PORT, '0.0.0.0', () => {
//     console.log(`Server running at http://localhost:${PORT}`);
//     console.log(`You can also access it using your machine's IP address: http://<your-ip-address>:${PORT}`);
// });



// Allow the server to listen on all network interfaces (0.0.0.0)
app.listen(PORT, '127.0.0.1', () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log(`You can also access it using your machine's IP address: http://127.0.0.1:${PORT}`);
});


// confernece



function generateLoginId() {
    return "ICACAUTH" + crypto.randomInt(100000, 999999); // Example: ICACAUTH123456
}

// ✅ REGISTER AUTHOR
app.post("/register_1", async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    // Validate passwords match
    if (password !== confirmPassword) {
        return res.status(400).json({ success: false, message: "Passwords do not match!" });
    }

    try {
        // Check if email already exists
        const [existingUsers] = await db.promise().query("SELECT * FROM con_author WHERE email = ?", [email]);
        if (existingUsers.length > 0) {
            return res.status(400).json({ success: false, message: "Email already registered!" });
        }

        // Generate unique Login ID
        let loginId;
        let loginIdExists;
        do {
            loginId = generateLoginId();
            [loginIdExists] = await db.promise().query("SELECT * FROM con_author WHERE loginId = ?", [loginId]);
        } while (loginIdExists.length > 0);

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert new author
        await db.promise().query(
            "INSERT INTO con_author (loginId, name, email, password) VALUES (?, ?, ?, ?)",
            [loginId, name, email, hashedPassword]
        );

        res.json({ success: true, message: "Registration successful!", loginId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});
app.post("/login_1", (req, res) => {
    const { loginId, password } = req.body;

    // Find user in the database
    const sql = "SELECT * FROM con_author WHERE loginId = ?";
    db.query(sql, [loginId], async (err, result) => {
        if (err) return res.status(500).json({ success: false, message: "Server error!" });

        if (result.length === 0) {
            return res.status(401).json({ success: false, message: "Invalid login ID!" });
        }

        const user = result[0];
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: "Invalid password!" });
        }

        // 🚨 Generate JWT WITHOUT SECRET KEY (Not Secure)
        const token = jwt.sign({ loginId: user.loginId }, null, { algorithm: "none" });

        res.json({ success: true, message: "Login successful!", token });
    });
});
app.post("/forgot-password-1", (req, res) => {
    const { email } = req.body;

    // Query to get user details (you can replace this with your actual database query)
    const sql = "SELECT loginId, password FROM con_author WHERE email = ?";
    db.query(sql, [email], (err, result) => {
        if (err) {
            return res.status(500).json({ success: false, message: "Server error!" });
        }

        if (result.length === 0) {
            return res.status(404).json({ success: false, message: "Email not found!" });
        }

        const user = result[0]; // Assuming only one result (email is unique)

        // Create a transporter with your email credentials (using environment variables)
        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: "thilakraja10@gmail.com", // Replace with your email
                pass: "tdai putr abny luxc" 
            }
        });

        // Prepare the email options
        const mailOptions = {
            from: process.env.EMAIL_USER, // Use the email from the .env file
            to: email,
            subject: "Password Recovery",
            text: `Your login credentials:\n\nLogin ID: ${user.loginId}\nPassword: ${user.password}`
        };

        // Send the email
        transporter.sendMail(mailOptions, (err, info) => {
            if (err) {
                return res.status(500).json({ message: "Error sending email", success: false });
            }
            res.json({ message: "Password sent to your email", success: true });
        });
    });
});
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.get("/author_dasboard1/:loginId", (req, res) => {
    const loginId = req.params.loginId.toLowerCase();

    db.query("SELECT * FROM con_author WHERE loginId = ?", [loginId], (err, authorResult) => {
        if (err || authorResult.length === 0) {
            return res.status(404).send("❌ Author not found.");
        }

        const author = authorResult[0];

        db.query("SELECT * FROM con_manuscripts WHERE loginId = ?", [loginId], (err, manuscriptResults) => {
            if (err) {
                console.error("🔥 Error fetching manuscripts:", err);
                return res.status(500).send("Error fetching manuscripts");
            }

            res.render("author_dasboard1", {
                author,
                manuscripts: manuscriptResults
            });
        });
    });
});

async function generatePaperId() {
    return new Promise((resolve, reject) => {
        db.query("SELECT paperId FROM con_manuscripts ORDER BY submissionDate DESC LIMIT 1", (err, result) => {
            if (err) return reject(err);
            if (result.length === 0) return resolve("ICACP1");

            const lastIdMatch = result[0].paperId.match(/\d+/);
            const lastId = lastIdMatch ? parseInt(lastIdMatch[0]) : 0;
            const newPaperId = `ICACP${lastId + 1}`;

            // Double-check that the new paperId does not exist
            db.query("SELECT paperId FROM con_manuscripts WHERE paperId = ?", [newPaperId], (err, existing) => {
                if (err) return reject(err);
                if (existing.length > 0) {
                    // If `newPaperId` already exists, increase by 1 and retry
                    resolve(`ICACP${lastId + 2}`);
                } else {
                    resolve(newPaperId);
                }
            });
        });
    });
}

// 🔹 API Route: Submit Manuscript
// app.post("/submit_1", upload2.single("file"), async (req, res) => {
//     try {
//         const { title, authors, email, abstract, keywords, comments, loginId, name, phone, gender, state, country, organization } = req.body;
//         const fileUrl = req.file ? `uploads/conference/${req.file.filename}` : null;

//         if (!title || !authors || !email || !abstract || !keywords || !loginId || !name || !phone || !gender || !state || !country || !organization) {
//             return res.status(400).json({ message: "All fields are required!" });
//         }
//         if (!req.file) {
//             return res.status(400).json({ message: "File upload failed!" });
//         }

//         const paperId = await generatePaperId();
        
//         const sql = `
//         INSERT INTO con_manuscripts 
//     (id, name, phone, gender, state, country, organization, paperId, title, authors, email, abstract, keywords, fileUrl, comments, reviewer, status, submissionDate, loginId) 
//     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
//         `;

//         console.log("📌 Inserting Manuscripts:", { id: uuidv4(), name, phone, gender, state, country, organization, paperId, title, authors, email, abstract, keywords, fileUrl, comments, loginId });

//         db.query(sql, [
//             uuidv4(), name, phone, gender, state, country, organization, 
//             paperId, title, authors, email, abstract, keywords, fileUrl, 
//             comments || "No comments", "None", "submitted", new Date(), loginId
//         ], (err) => {
//             if (err) {
//                 console.error("🔥 MySQL Error:", err);
//                 return res.status(500).json({ success: false, message: "Error submitting manuscript.", error: err.sqlMessage });
//             }
//             res.json({ success: true, message: "✅ Manuscript submitted successfully!", redirectURL: `/author_dasboard1/${loginId}` });
//         });

//     } catch (error) {
//         console.error("❌ Submission Error:", error);
//         res.status(500).json({ message: "Internal Server Error" });
//     }
// });
app.post("/submit_1", upload2.single("file"), async (req, res) => {
    try {
        const { title, authors, email, abstract, keywords, comments, loginId, name, phone, gender, state, country, organization } = req.body;
        const fileUrl = req.file ? `uploads/conference/${req.file.filename}` : null;

        if (!title || !authors || !email || !abstract || !keywords || !loginId || !name || !phone || !gender || !state || !country || !organization) {
            return res.status(400).json({ message: "All fields are required!" });
        }

        if (!req.file) {
            return res.status(400).json({ message: "File upload failed!" });
        }

        const paperId = await generatePaperId();

        const sql = `
            INSERT INTO con_manuscripts 
            (id, name, phone, gender, state, country, organization, paperId, title, authors, email, abstract, keywords, fileUrl, comments, reviewer, status, submissionDate, loginId) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const uniqueId = uuidv4();
        db.query(sql, [
            uniqueId, name, phone, gender, state, country, organization, 
            paperId, title, authors, email, abstract, keywords, fileUrl, 
            comments || "No comments", "None", "submitted", new Date(), loginId
        ], async (err) => {
            if (err) {
                console.error("🔥 MySQL Error:", err);
                return res.status(500).json({ success: false, message: "Error submitting manuscript.", error: err.sqlMessage });
            }

            // ✅ Send email after successful DB insert
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: 'thilakraja10@gmail.com',       // 🔁 Replace with your Gmail
                    pass: 'tunw uvnn dujq khds'           // 🔁 Replace with your Gmail App Password
                }
            });

            const mailOptions = {
                from: 'your-email@gmail.com',
                to: email,
                subject: 'ICAC 2025 - Manuscript Submission Confirmation',
                html: `
                    <h3>Dear ${name},</h3>
                    <p>Thank you for submitting your manuscript to ICAC 2025.</p>
                    <p><strong>Paper ID:</strong> ${paperId}</p>
                    <p><strong>Title:</strong> ${title}</p>
                    <p>We will review your submission and get back to you shortly.</p>
                    <br/>
                    <p>Regards,<br/>ICAC 2025 Team</p>
                `
            };

            try {
                await transporter.sendMail(mailOptions);
                console.log("📧 Confirmation email sent to:", email);
            } catch (emailError) {
                console.error("❌ Error sending email:", emailError);
            }

            res.json({ success: true, message: "✅ Manuscript submitted successfully!", redirectURL: `/author_dasboard1/${loginId}` });
        });

    } catch (error) {
        console.error("❌ Submission Error:", error);
        res.status(500).json({ message: "Internal Server Error" });
    }
});


app.put("/update-status_1/:paperId", (req, res) => {
    const { paperId } = req.params;
    const { status } = req.body;

    db.query("UPDATE con_manuscripts SET status = ? WHERE paperId = ?", [status, paperId], (err, result) => {
        if (err) {
            console.error("❌ Update Error:", err);
            return res.status(500).json({ message: "Internal Server Error" });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "❌ Manuscript not found!" });
        }
        res.json({ message: "✅ Status updated successfully!" });
    });
});

// 🔹 API Route: View Manuscript by Paper ID
app.get("/submission1/:paperId", (req, res) => {
    const { paperId } = req.params;

    db.query("SELECT * FROM con_manuscripts WHERE paperId = ?", [paperId], (err, result) => {
        if (err) {
            console.error("❌ Fetch Error:", err);
            return res.status(500).send("Server Error");
        }
        if (result.length === 0) {
            return res.status(404).send("❌ Manuscript not found");
        }
        res.render("submission_details1", { paper: result[0] });
    });
});
app.get("/get-papers_1", (req, res) => {
    const sql = `
        SELECT paperId, title, authors, email, submissionDate, reviewer
        FROM con_manuscripts
        ORDER BY CAST(SUBSTRING(paperId, 6) AS UNSIGNED) ASC
    `;

    db.query(sql, (err, results) => {
        if (err) {
            console.error("Error fetching papers:", err);
            return res.status(500).json({ error: "Error fetching papers" });
        }
        res.json(results);
    });
});

app.post('/reviewer5-register_1', async (req, res) => {
    const { name, email, password } = req.body;

    // Check if all required fields are provided
    if (!name || !email || !password) {
        return res.status(400).json({ message: 'All fields are required.' });
    }

    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into the reviewerlo table
    const query = 'INSERT INTO con_reviewer (name, email, password) VALUES (?, ?, ?)';
    db.query(query, [name, email, hashedPassword], (err, result) => {
        if (err) {
            console.error('Error inserting user:', err);
            return res.status(500).json({ message: 'Internal server error.' });
        }
        res.status(201).json({ message: 'User registered successfully!' });
    });
});

// User Login Endpoint
app.post('/reviewer5-login_1', (req, res) => {
    const { email, password } = req.body;

    // Check if both fields are provided
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }

    // Find the user by email
    const query = 'SELECT * FROM con_reviewer WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error('Error fetching user:', err);
            return res.status(500).json({ message: 'Internal server error.' });
        }
        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        // Compare the password
        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid email or password.' });
        }
        // const token = jwt.sign({ id: user.id, role: user.name }, "secretkey", { expiresIn: "1h" });

        // Generate a token
        // const token = jwt.sign({ loginId: user.loginId }, null, { algorithm: "none" });
        const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, SECRET_KEY, { expiresIn: "1h" });

        res.json({ message: "Login successful", reviewer: { name: user.name, email: user.email }, token });
        // res.status(200).json({
        //     message: 'Login successful!',
        //     token: token
        // });
    });
});

app.get("/get-reviewers_1", (req, res) => {
    const sql = "SELECT * FROM con_reviewerinfo";
    db.query(sql, (err, results) => {
        if (err) {
            res.status(500).json({ error: "Database error" });
        } else {
            res.json(results);
        }
    });
});



// Add Reviewer Route


app.post("/add-reviewer_1", (req, res) => {
    const { name, affiliation, email, profile, researchArea } = req.body;

    if (!name || !email) {
        return res.status(400).json({ message: "Name and Email are required" });
    }

    const sql = `INSERT INTO con_reviewerinfo (name, affiliation, email, profile, research_area) VALUES (?, ?, ?, ?, ?)`;

    db.query(sql, [name, affiliation, email, profile || "N/A", researchArea || "N/A"], (err, result) => {
        if (err) {
            console.error("Error adding reviewer:", err);
            return res.status(500).json({ message: "Error adding reviewer", error: err.sqlMessage });
        }

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: "thilakraja10@gmail.com", // Replace with your email
                pass: "tdai putr abny luxc"  // ✅ Securely use environment variable
            }
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Reviewer Added Successfully',
            text: `Hello ${name},\n\nYou have been successfully added as a reviewer to our system.\n\nThank you,\nThe Team`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("Error sending email:", error);
                return res.status(500).json({ message: "Reviewer added, but email could not be sent", error: error.message });
            }
            console.log("✅ Email sent: " + info.response);
            res.status(201).json({ message: "Reviewer added successfully and email sent!" });
        });
    });
});



app.delete("/delete-reviewer_1/:id", (req, res) => {
    const reviewerId = req.params.id;
    console.log("Received reviewer ID for deletion:", reviewerId);

    if (!reviewerId || isNaN(reviewerId)) {
        return res.status(400).json({ message: "Invalid reviewer ID" });
    }

    const sql = "DELETE FROM con_reviewerinfo WHERE id = ?";
    db.query(sql, [reviewerId], (err, result) => {
        if (err) {
            console.error("Error deleting reviewer:", err);
            return res.status(500).json({ message: "Database error" });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Reviewer not found!" });
        }

        res.json({ message: "Reviewer deleted successfully!" });
    });
});


// const nodemailer = require('nodemailer');

// app.post('/assign-reviewer_1', async (req, res) => {
//     // Log the incoming request body to check paperId and reviewerId
//     console.log('Request Body:', req.body);
   
//     const { paperId, reviewerId, reviewerName } = req.body;
//     const status = "Under Review";
//     // Validate the incoming data
//     if (!paperId || !reviewerId || !reviewerName) {
//         return res.status(400).json({ message: 'Missing paperId, reviewerId, or reviewerName' });
//     }

//     console.log('Assigning reviewer:', { paperId, reviewerId, reviewerName });

//     try {
//         // SQL query to update the paper with the reviewer name
//         const updateQuery = 'UPDATE con_manuscripts SET reviewer = ?,status=? WHERE paperId = ?';
//         await db.promise().query(updateQuery, [reviewerName, status,paperId]);

//         // Optionally, get reviewer details (like name or email) from the `reviewers` table
//         const getReviewerQuery = 'SELECT name, email FROM con_reviewerinfo WHERE name = ?';
//         const [reviewerData] = await db.promise().query(getReviewerQuery, [reviewerName]);

//         if (reviewerData.length === 0) {
//             return res.status(404).json({ message: 'Reviewer not found' });
//         }

//         const reviewerNameFromDb = reviewerData[0]?.name || 'Unknown Reviewer';
//         const reviewerEmail = reviewerData[0]?.email;

//         // Ensure the email is correct before proceeding
//         if (!reviewerEmail) {
//             return res.status(400).json({ message: 'Reviewer email is missing' });
//         }

//         console.log('Reviewer email:', reviewerEmail); // Debugging line

//         // Configure Nodemailer
//         let transporter = nodemailer.createTransport({
//             service: 'gmail', // You can use other services like Outlook, SendGrid, etc.
//             auth: {
//                 user: "thilakraja10@gmail.com", // Replace with your email
//                 pass: "tdai putr abny luxc" // App password (if 2FA is enabled)
//             }
//         });

//         // Set up email data
//         let mailOptions = {
//             from: 'your-email@gmail.com',
//             to: reviewerEmail,
//             subject: 'New Paper Review Assignment',
//             text: `Dear ${reviewerNameFromDb},\n\nYou have been assigned to review the paper with Paper ID: ${paperId}.\n\nBest regards,\nYour Paper Management Team`
//         };

//         // Send email
//         transporter.sendMail(mailOptions, (error, info) => {
//             if (error) {
//                 console.log('Error sending email:', error);
//                 return res.status(500).json({ message: 'Error sending email', error: error.message });
//             }

//             console.log('Email sent: ' + info.response); // This logs the Gmail SMTP response

//             // Check if email was actually delivered
//             if (info.accepted && info.accepted.length > 0) {
//                 console.log('Email successfully sent to:', info.accepted);
//             } else {
//                 console.error('Email was not accepted by Gmail SMTP server.');
//             }
//         });

//         // Respond with success message
//         res.status(200).json({
//             message: 'Reviewer assigned successfully!',
//             reviewerName: reviewerNameFromDb
//         });
//     } catch (err) {
//         console.error('Error assigning reviewer:', err);
//         res.status(500).json({ message: 'Error assigning reviewer', error: err.message });
//     }
// });
app.post('/assign-reviewer', async (req, res) => {
    console.log('Request Body:', req.body);

    const { paperId, reviewerId, reviewerName } = req.body;
    const status = "Under Review";

    if (!paperId || !reviewerId || !reviewerName) {
        return res.status(400).json({ message: 'Missing paperId, reviewerId, or reviewerName' });
    }

    console.log('Assigning reviewer:', { paperId, reviewerId, reviewerName });

    try {
        // 1. Update manuscript with reviewer and status
        const updateQuery = 'UPDATE manuscript SET reviewer = ?, status = ? WHERE paperId = ?';
        await db.promise().query(updateQuery, [reviewerName, status, paperId]);

        // 2. Get reviewer info
        const [reviewerData] = await db.promise().query('SELECT name, email FROM reviewers WHERE name = ?', [reviewerName]);
        if (reviewerData.length === 0) {
            return res.status(404).json({ message: 'Reviewer not found' });
        }
        const reviewerNameFromDb = reviewerData[0].name;
        const reviewerEmail = reviewerData[0].email;

        // 3. Get author info
        const [authorData] = await db.promise().query('SELECT title, email FROM manuscript WHERE paperId = ?', [paperId]);
        if (authorData.length === 0) {
            return res.status(404).json({ message: 'Author not found for this paperId' });
        }
        const paperTitle = authorData[0].title;
        const authorEmail = authorData[0].email;

        // 4. Setup mail transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'thilakraja10@gmail.com', // Your Gmail
                pass: 'tdai putr abny luxc'      // App Password
            }
        });

        // 5. Mail to Reviewer
        const reviewerMailOptions = {
            from: 'your-email@gmail.com',
            to: reviewerEmail,
            subject: 'New Paper Review Assignment',
            text: `Dear ${reviewerNameFromDb},\n\nYou have been assigned to review the paper titled: "${paperTitle}" (Paper ID: ${paperId}).\n\nPlease log in to your dashboard to review the paper.\n\nBest regards,\nIJSRC Editorial Team`
        };

        // 6. Mail to Author
        const authorMailOptions = {
            from: 'your-email@gmail.com',
            to: authorEmail,
            subject: 'Your Paper is Under Review - IJSRC',
            text: `Dear Author,\n\nYour manuscript titled "${paperTitle}" (Paper ID: ${paperId}) has been assigned to a reviewer and is now under review.\n\nWe will notify you once the review process is complete.\n\nThank you for your submission.\n\nBest regards,\nIJSRC Editorial Team`
        };

        // 7. Send emails
        await transporter.sendMail(reviewerMailOptions);
        console.log("✅ Reviewer email sent to:", reviewerEmail);

        await transporter.sendMail(authorMailOptions);
        console.log("✅ Author email sent to:", authorEmail);

        res.status(200).json({
            message: 'Reviewer assigned and emails sent successfully!',
            reviewerName: reviewerNameFromDb
        });

    } catch (err) {
        console.error('❌ Error assigning reviewer:', err);
        res.status(500).json({ message: 'Error assigning reviewer', error: err.message });
    }
});

app.post("/save-comments_1", (req, res) => {
    const { papers } = req.body;

    if (!papers || papers.length === 0) {
        return res.status(400).json({ message: "No data provided" });
    }

    let updateQueries = papers.map(paper => {
        return new Promise((resolve, reject) => {
            const query = "UPDATE con_manuscripts SET status = ?, comments = ? WHERE title = ?";
            db.query(query, [paper.status, paper.comments, paper.title], (err, result) => {
                if (err) reject(err);
                else resolve(result);
            });
        });
    });

    Promise.all(updateQueries)
        .then(() => res.json({ message: "Data saved successfully" }))
        .catch(err => res.status(500).json({ message: "Error saving data", error: err }));
});


app.get("/api/reviewer-comments_1", (req, res) => {
    const query = "SELECT paperId, title AS paperTitle, reviewer AS reviewerName, comments, status FROM con_manuscripts ORDER BY CAST(SUBSTRING(paperId, 7) AS UNSIGNED) ASC";

    db.query(query, (err, results) => {
        if (err) {
            return res.status(500).json({ error: "Error fetching reviewer comments", details: err });
        }

        // Format response to match previous MongoDB structure
        res.json(results.map(paper => ({
            _id: paper.paperId,
            paperTitle: paper.paperTitle,
            reviewerName: paper.reviewerName,
            comments: paper.comments || "No comments",
            status: paper.status
        })));
    });
});

app.get("/assigned-papers_1", (req, res) => {
    const reviewerName = req.query.name; // Fetch from query parameter

    if (!reviewerName) {
        return res.status(400).json({ message: "Reviewer name is required" });
    }

    const query = "SELECT * FROM con_manuscripts WHERE reviewer = ?";
    db.query(query, [reviewerName], (err, results) => {
        if (err) {
            return res.status(500).json({ message: "Database error", error: err });
        }

        if (results.length === 0) {
            return res.json({ message: "No papers assigned", papers: [] });
        }

        res.json({ reviewerName, papers: results });
    });
});

app.post("/submit-payment", upload.single("receipt"), (req, res) => {
    const { paperId, upiId, paymentDate } = req.body;
    const receiptPath = req.file ? `uploads/payment/${req.file.filename}` : null;
    console.log(`File uploaded to: ${req.file.filename}`);

    const paymentId = uuidv4().replace(/-/g, '').substring(0, 24);

    if (!paperId || !upiId || !paymentDate || !receiptPath) {
        return res.json({ success: false, message: "All fields are required!" });
    }

    const query = `INSERT INTO con_payments (id, paperId, upiId, paymentDate, receiptPath) VALUES (?, ?, ?, ?, ?)`;
    db.query(query, [paymentId, paperId, upiId, paymentDate, receiptPath], (err, result) => {
        if (err) {
            console.error("MySQL Error: " + err);
            return res.json({ success: false, message: "Database error!" });
        }

        res.json({ success: true, message: "Payment recorded successfully!" });
    });
});
app.get("/author_dashboard1/:loginId", async (req, res) => {
    try {
        const author = await User.findOne({ loginId: req.params.loginId });

        if (!author) {
            return res.status(404).send("Author not found");
        }

        const manuscripts = await Manuscript.find({ email: author.email });

        // Assign correct file URLs for each manuscript
        manuscripts.forEach(paper => {
            paper.fileUrl = `/uploads/conference/${paper.fileName}`;
        });

        res.render("author_dashboard1", { author, manuscripts });
    } catch (error) {
        console.error("Error loading dashboard:", error);
        res.status(500).send("Server Error");
    }
});


app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.get("/submission1/:paperId", async (req, res) => {
    try {
        const paper = await Manuscript.findOne({ paperId: req.params.paperId });
        if (!paper) return res.status(404).send("Manuscript not found");

        // Ensure correct file path
        paper.fileUrl = `/uploads/conference/${paper.fileName}`;

        res.render("submission_details1", { paper });
    } catch (error) {
        res.status(500).send("Server Error");
    }
});




app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// === Directory Paths ===
const uploadPath3 = 'uploads/signatures';
const pdfPath = './public/pdfs';

if (!fs.existsSync(uploadPath3)) fs.mkdirSync(uploadPath3, { recursive: true });
if (!fs.existsSync(pdfPath)) fs.mkdirSync(pdfPath, { recursive: true });


// === PDF Generation Function ===

const storage4= multer.diskStorage({
    destination: 'uploads/signatures/',
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname).toLowerCase(); // Get file extension
        const fileName = `${Date.now()}-${file.originalname.replace(/\s+/g, '_')}`;
        cb(null, fileName);
    }
});

const upload4 = multer({
    storage: storage4,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        const fileTypes = /\.(jpeg|jpg|png)$/; // Allow only .jpeg, .jpg, .png
        const extname = fileTypes.test(path.extname(file.originalname).toLowerCase());
        const mimeType = file.mimetype.startsWith('image/');

        if (extname && mimeType) {
            return cb(null, true);
        } else {
            cb(new Error('Error: Only JPEG, JPG, and PNG files are allowed!'));
        }
    }
});
const SignaturePath = async (userId) => {
    const user = await User.findById(userId);
    if (user && user.signature) {
        return path.join(__dirname, 'uploads', 'signatures', user.signature);
    }
    return null; // If no signature is found
};



// Handle form submission
app.post('/conregister', upload4.single('signature'), (req, res) => {
    const {
        name, gender, designation, organization, address, email, mobile,
        role, paperTitle, paperId, registrationFee, paymentMethod,
        transactionId, paymentDate, place, date,
    } = req.body;
    const signature = req.file ? req.file.filename : null;


    // Insert into MySQL
    const sql = `INSERT INTO con_registration (name, gender, designation, organization, address, email, mobile, role, paperTitle, paperId, registrationFee, paymentMethod, transactionId, paymentDate, place, date, signature) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

    db.query(sql, [
        name, gender, designation, organization, address, email, mobile,
        role, paperTitle, paperId, registrationFee, paymentMethod,
        transactionId, paymentDate, place, date, signature
    ], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });

        // Generate PDF
        const filePath = `uploads/pdfs/ICAC2025_${result.insertId}.pdf`;
        generatePDF(req.body,signature, filePath, () => {
            res.json({ pdfPath: `/${filePath}` });
        });
    });
});


// PDF generation function
function generatePDF(data, signature,filePath, callback) {
    const doc = new PDFDocument({ margin: 50 });
    const stream = fs.createWriteStream(filePath);

    doc.pipe(stream);

    // ✅ Add Logo in Top Right Corner
    const logoPath = path.join(__dirname, 'public', 'img', 'logo1.png');
    if (fs.existsSync(logoPath)) {
        const logoWidth = 80;
        const logoHeight = 80;
    
        // Left-align the logo (X = 30 for some padding)
        doc.image(logoPath, 30, 30, {
            width: logoWidth,
            height: logoHeight
        });
    }

    // ✅ Header
    doc
        .font('Helvetica-Bold')
        .fontSize(16)
        .fillColor('#4285F4')
        .text('Department of Computer Science', { align: 'center' });

    doc
        .font('Helvetica')
        .fontSize(14)
        .fillColor('#555555')
        .text('Bharathiar University', { align: 'center' });

    doc
        .font('Helvetica-Bold')
        .fontSize(14)
        .fillColor('#EA4335')
        .text('International Conference on Advanced Computing', { align: 'center' });

    doc
        .font('Helvetica-Bold')
        .fontSize(14)
        .fillColor('#34A853')
        .text('(ICAC-2025)', { align: 'center' });

    // ✅ Date with superscript (centered)
    const dateX = (doc.page.width - doc.widthOfString('18th & 19th September 2025')) / 2;
    let y = doc.y + 5;

    doc
        .font('Helvetica')
        .fontSize(12)
        .fillColor('#000000')
        .text('18', dateX, y, { continued: true })
        .fontSize(8)
        .text('th', { baseline: 'sup', continued: true })
        .fontSize(12)
        .text(' & 19', { continued: true })
        .fontSize(8)
        .text('th', { baseline: 'sup', continued: true })
        .fontSize(12)
        .text(' September 2025');

    doc.moveDown(1);

    // ✅ Title (center aligned)
    const text = 'ICAC 2025 Registration Receipt';
    const textWidth = doc.widthOfString(text);
    const centerX = (doc.page.width - textWidth) / 2;

    doc
        .fontSize(15)
        .fillColor('#ff5733')
        .text(text, centerX, doc.y);

    doc.moveDown(1);

    // ✅ Table Dimensions
    const column1Width = 200;
    const column2Width = 300;
    const rowHeight = 30;
    const startX = 70;
    y = doc.y;

    // ✅ Table Header Background
    doc
        .rect(startX, y, column1Width, rowHeight)
        .rect(startX + column1Width, y, column2Width, rowHeight)
        .fillColor('#D1E8FF')
        .fill();

    // ✅ Table Header Text
    doc
        .fillColor('#000000')
        .font('Helvetica-Bold')
        .fontSize(12)
        .text('Field', startX + 5, y + 8, { width: column1Width - 10, align: 'left' })
        .text('Details', startX + column1Width + 5, y + 8, { width: column2Width - 10, align: 'left' });

    y += rowHeight;
    console.log('Data:', data);
    // ✅ Table Data
    const tableData = [
        ['Name', data.name],
        ['Gender', data.gender],
        ['Designation', data.designation],
        ['organization/Institution', data.organization],
        ['Postal Address', data.address],
        ['Email', data.email],
        ['Mobile', data.mobile],
        ['Role', data.role],
        ['Paper Title', data.paperTitle],
        ['Paper ID', data.paperId],
        ['Registration Fee', `₹ ${data.registrationFee}`],
        ['Payment Method', data.paymentMethod],
        ['Transaction ID', data.transactionId],
        ['Payment Date', data.paymentDate],
        ['Place', data.place],
        ['Date', data.date ? data.date.toUpperCase() : 'N/A']
    ];

    tableData.forEach((row, index) => {
        // ✅ Alternate Row Background Color
        doc
            .rect(startX, y, column1Width, rowHeight)
            .rect(startX + column1Width, y, column2Width, rowHeight)
            .fillColor(index % 2 === 0 ? '#F5F5F5' : '#FFFFFF')
            .fill();

        // ✅ Draw Cell Text
        doc
            .fillColor('#000000')
            .font('Helvetica')
            .fontSize(12)
            .text(row[0] || '', startX + 5, y + 8, { width: column1Width - 10, align: 'left' })
            .text(row[1] || 'N/A', startX + column1Width + 5, y + 8, { width: column2Width - 10, align: 'left' });

        // ✅ Draw Cell Borders
        doc
            .rect(startX, y, column1Width, rowHeight)
            .rect(startX + column1Width, y, column2Width, rowHeight)
            .lineWidth(1)
            .strokeColor('#cccccc')
            .stroke();

        y += rowHeight;
    });

    // ✅ Signature Row
    y += 20;

    const signaturePath = signature 
    ? path.resolve(__dirname, 'uploads/signatures/', signature)
    : null;

    console.log('Signature Path:',  signature); // ✅ Debug log

    doc
        .font('Helvetica-Bold')
        .fontSize(12)
        .text('Signature:', startX, y);

    const signatureWidth = 100;
    const signatureHeight = 50;

    if (signaturePath && fs.existsSync(signaturePath)) {
        console.log('Signature file exists ✅');
        // ✅ Display signature image
        doc.image(signaturePath, startX + 100, y - 10, {
            width: signatureWidth,
            height: signatureHeight
        });
    } else {
        console.log('Signature file missing ❌');
        // ✅ Draw empty signature placeholder
        doc
            .rect(startX + 100, y - 10, signatureWidth, signatureHeight)
            .strokeColor('#cccccc')
            .lineWidth(1)
            .stroke();
    }

    // ✅ End Document
    doc.end();

    stream.on('finish', callback);
}
// === SERVING STATIC FILES FOR PDF DOWNLOAD ===
app.use('/pdfs', express.static(path.join(__dirname, 'uploads', 'pdfs')));


app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.post("/reset-password_1", async (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ success: false, message: "All fields are required!" });
    }

    try {
        const [existingUser] = await db.promise().query(
           "SELECT loginId, password FROM con_author WHERE email = ?", 
            [email]
        );

        if (existingUser.length === 0) {
            return res.status(404).json({ success: false, message: "Email not found!" });
        }

        // Hash new password using bcrypt
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        console.log("hashedPassword",hashedPassword);


        await db.promise().query(
            "UPDATE con_author SET password = ? WHERE email = ?", 
            [hashedPassword, email]
        );

        res.json({ success: true, message: "Password reset successful!" });
    } catch (error) {
        console.error("Password reset error:", error);
        res.status(500).json({ success: false, message: "Server error. Please try again." });
    }
});
app.post("/reset-password", async (req, res) => {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
        return res.status(400).json({ success: false, message: "All fields are required!" });
    }

    try {
        const [existingUser] = await db.promise().query(
           "SELECT loginId, password FROM authors WHERE email = ?", 
            [email]
        );

        if (existingUser.length === 0) {
            return res.status(404).json({ success: false, message: "Email not found!" });
        }

        // Hash new password using bcrypt
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await db.promise().query(
            "UPDATE authors SET password = ? WHERE email = ?", 
            [hashedPassword, email]
        );

        res.json({ success: true, message: "Password reset successful!" });
    } catch (error) {
        console.error("Password reset error:", error);
        res.status(500).json({ success: false, message: "Server error. Please try again." });
    }
});



app.get('/check-paper-id', (req, res) => {
    const { paperId } = req.query;
    
    const sql = "SELECT * FROM con_manuscripts WHERE paperId = ?";
    db.query(sql, [paperId], (err, result) => {
        if (err) {
            console.error("Database Query Error:", err);
            return res.status(500).json({ exists: false, error: "Internal Server Error" });
        }

        if (result.length > 0) {
            res.json({
                exists: true,
                title: result[0].title, 
                name: result[0].name,
                email: result[0].email,
                phone: result[0].phone,
                gender: result[0].gender,
                organization: result[0].organization
               
            });
        } else {
            res.json({ exists: false });
        }
    });
});
app.get("/getPaperId", (req, res) => {
    const { paperId } = req.query; // Get paperId from query parameters

    if (!paperId) {
        return res.status(400).json({ error: "paperId is required" });
    }

    const sql = "SELECT * FROM manuscript WHERE paperId = ?";
    db.query(sql, [paperId], (err, result) => {
        if (err) return res.status(500).send(err);
        if (result.length > 0) {
            res.json({ paperId: result[0].paperId });
        } else {
            res.json({ paperId: "" });
        }
    });
});

app.post("/submitReview", (req, res) => {
    const { paperId, originality, relevance, methodology, dataAnalysis, language, recommendation } = req.body;

    if (!paperId) {
        return res.status(400).json({ message: "Paper ID is required" });
    }

    const pdfFilePath = `uploads/comment/review_${paperId}.pdf`;

    const sql = `INSERT INTO recomments (paperId, originality, relevance, methodology, data_analysis, language, recommendation, pdf_path)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    const values = [paperId, originality, relevance, methodology, dataAnalysis, language, recommendation, pdfFilePath];

    db.query(sql, values, (err) => {
        if (err) return res.status(500).json({ message: "Database error", error: err });

        db.query(`UPDATE manuscript SET comments = ? WHERE paperId = ?`, [pdfFilePath, paperId], (updateErr) => {
            if (updateErr) return res.status(500).json({ message: "Failed to update manuscript", error: updateErr });

            // ✅ Generate PDF and respond only after successful generation
            generatePDF1(paperId, originality, relevance, methodology, dataAnalysis, language, recommendation, () => {
                return res.json({ success: true, message: "Review submitted successfully!", pdfPath: `/downloadReviewPDF?paperId=${paperId}` });
            });
        });
    });
});

// ✅ Function to generate PDF
function generatePDF1(paperId, originality, relevance, methodology, dataAnalysis, language, recommendation, callback) {
    console.log("paperId:", paperId, "Type:", typeof paperId);
    const pdfFilePath = path.join(__dirname, "uploads", "comment", `review_${paperId}.pdf`);
    console.log("paperId:", paperId, "Type:", typeof paperId);


    const doc = new PDFDocument();
    const stream = fs.createWriteStream(pdfFilePath);

    doc.pipe(stream);
    doc.fontSize(20).text("Review Report", { align: "center" }).moveDown();
    doc.fontSize(14).text(`Paper ID: ${paperId}`).moveDown();
    doc.fontSize(12).text(`Originality: ${originality}`).moveDown();
    doc.fontSize(12).text(`Relevance: ${relevance}`).moveDown();
    doc.fontSize(12).text(`Methodology: ${methodology}`).moveDown();
    doc.fontSize(12).text(`Data Analysis: ${dataAnalysis}`).moveDown();
    doc.fontSize(12).text(`Language: ${language}`).moveDown();
    doc.fontSize(12).text(`Recommendation: ${recommendation}`).moveDown();

    doc.end();

    stream.on("finish", callback);
}

// ✅ API to download the generated PDF
app.get("/downloadReviewPDF", (req, res) => {
    const { paperId } = req.query;

    if (!paperId) {
        return res.status(400).json({ message: "Paper ID is required" });
    }

    const pdfFilePath = path.join(__dirname, "uploads", "comment", `review_${paperId}.pdf`);

    fs.access(pdfFilePath, fs.constants.F_OK, (err) => {
        if (err) {
            return res.status(404).json({ message: "File not found" });
        }

        res.download(pdfFilePath, `review_${paperId}.pdf`, (err) => {
            if (err) {
                console.error("Download error:", err);
                res.status(500).json({ message: "Error downloading file" });
            }
        });
    });
});

// ✅ API to update manuscript status
// app.post("/api/update-status", (req, res) => {
//     const { paperId } = req.body;

//     if (!paperId) {
//         return res.status(400).json({ message: "Paper ID is required" });
//     }

//     console.log("Updating status for Paper ID:", paperId);

//     const sql = `UPDATE manuscript SET status = 'Reviewercomment' WHERE paperId = ?`;

//     db.query(sql, [paperId], (err) => {
//         if (err) return res.status(500).json({ message: "Database update failed", error: err });

//         res.json({ success: true, message: "Status updated to Reviewer Comment!" });
//     });
// });
app.post("/api/update-status", async (req, res) => {
    const { paperId } = req.body;

    if (!paperId) {
        return res.status(400).json({ message: "Paper ID is required" });
    }

    console.log("Updating status for Paper ID:", paperId);

    const updateSql = `UPDATE manuscript SET status = 'Reviewercomment' WHERE paperId = ?`;

    try {
        // 1. Update the status
        await db.promise().query(updateSql, [paperId]);

        // 2. Get author's email and paper title
        const [result] = await db.promise().query(
            "SELECT email, title FROM manuscript WHERE paperId = ?",
            [paperId]
        );

        if (result.length === 0) {
            return res.status(404).json({ message: "Paper not found" });
        }

        const { email, title } = result[0];

        // 3. Setup Nodemailer transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'thilakraja10@gmail.com',
                pass: 'tdai putr abny luxc'
            }
        });

        // 4. Email content
        const mailOptions = {
            from: 'your-email@gmail.com',
            to: email,
            subject: 'Reviewer Comments Received - ICAC 2025',
            text: `Dear Author,\n\nYour manuscript titled "${title}" (Paper ID: ${paperId}) has received reviewer comments.\n\nPlease log in to your author dashboard to view the feedback and respond accordingly.\n\nThank you,\nICAC 2025 Review Committee`
        };

        // 5. Send email
        await transporter.sendMail(mailOptions);
        console.log(`✅ Email sent to author: ${email}`);

        // 6. Respond
        res.json({ success: true, message: "Status updated to Reviewer Comment and email sent to author." });

    } catch (err) {
        console.error("❌ Error updating status or sending email:", err);
        res.status(500).json({ message: "Error processing request", error: err.message });
    }
});
// app.post("/api/update-status_1", (req, res) => {
//     const { paperId } = req.body;

//     if (!paperId) {
//         return res.status(400).json({ message: "Paper ID is required" });
//     }

//     console.log("Updating status for Paper ID:", paperId);

//     const sql = `UPDATE con_manuscripts SET status = 'Reviewercomment' WHERE paperId = ?`;

//     db.query(sql, [paperId], (err) => {
//         if (err) return res.status(500).json({ message: "Database update failed", error: err });

//         res.json({ success: true, message: "Status updated to Reviewer Comment!" });
//     });
// });
app.post("/api/update-status_1", async (req, res) => {
    const { paperId } = req.body;

    if (!paperId) {
        return res.status(400).json({ message: "Paper ID is required" });
    }

    console.log("📌 Updating status for Paper ID:", paperId);

    const updateSql = `UPDATE con_manuscripts SET status = 'Reviewercomment' WHERE paperId = ?`;

    try {
        // 1. Update status
        await db.promise().query(updateSql, [paperId]);

        // 2. Get author's email and paper title
        const [result] = await db.promise().query(
            "SELECT email, title FROM con_manuscripts WHERE paperId = ?",
            [paperId]
        );

        if (result.length === 0) {
            return res.status(404).json({ message: "Paper not found" });
        }

        const { email, title } = result[0];

        // 3. Setup nodemailer
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'thilakraja10@gmail.com',     // your Gmail
                pass: 'tdai putr abny luxc'          // your App password
            }
        });

        // 4. Email options
        const mailOptions = {
            from: 'your-email@gmail.com',
            to: email,
            subject: 'Reviewer Comments Received - ICAC 2025',
            text: `Dear Author,\n\nYour conference manuscript titled "${title}" (Paper ID: ${paperId}) has received reviewer comments.\n\nPlease log in to your author dashboard to check the comments and take necessary action.\n\nRegards,\nICAC 2025 Committee`
        };

        // 5. Send the email
        await transporter.sendMail(mailOptions);
        console.log("✅ Email sent to author:", email);

        res.json({
            success: true,
            message: "Status updated to Reviewer Comment and email sent to author."
        });

    } catch (err) {
        console.error("❌ Error:", err);
        res.status(500).json({
            message: "Internal Server Error",
            error: err.message
        });
    }
});
app.post("/submitReview_1", (req, res) => {
    const { paperId, originality, relevance, methodology, dataAnalysis, language, recommendation } = req.body;

    if (!paperId) {
        return res.status(400).json({ message: "Paper ID is required" });
    }

    const pdfFilePath = `uploads/comment1/review_${paperId}.pdf`;

    const sql = `INSERT INTO recomments1 (paperId, originality, relevance, methodology, data_analysis, language, recommendation, pdf_path)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    const values = [paperId, originality, relevance, methodology, dataAnalysis, language, recommendation, pdfFilePath];

    db.query(sql, values, (err) => {
        if (err) return res.status(500).json({ message: "Database error", error: err });

        db.query(`UPDATE con_manuscripts  SET comments = ? WHERE paperId = ?`, [pdfFilePath, paperId], (updateErr) => {
            if (updateErr) return res.status(500).json({ message: "Failed to update manuscript", error: updateErr });

            // ✅ Generate PDF and respond only after successful generation
            generatePDF2(paperId, originality, relevance, methodology, dataAnalysis, language, recommendation, () => {
                return res.json({ success: true, message: "Review submitted successfully!", pdfPath: `/downloadReviewPDF_1?paperId=${paperId}` });
            });
        });
    });
});

// ✅ Function to generate PDF
function generatePDF2(paperId, originality, relevance, methodology, dataAnalysis, language, recommendation, callback) {
    console.log("paperId:", paperId, "Type:", typeof paperId);
    const pdfFilePath1 = path.join(__dirname, "uploads", "comment1", `review_${paperId}.pdf`);

    const doc = new PDFDocument();
    const stream = fs.createWriteStream(pdfFilePath1);

    doc.pipe(stream);

    // Title
    doc.fontSize(20).text("Review Report", { align: "center" }).moveDown();

    // Paper ID
    doc.fontSize(14).text(`Paper ID: ${paperId}`).moveDown();

    // Define table rows
    const tableData = [
        { label: "Originality", value: originality },
        { label: "Relevance", value: relevance },
        { label: "Methodology", value: methodology },
        { label: "Data Analysis", value: dataAnalysis },
        { label: "Language", value: language },
        { label: "Recommendation", value: recommendation }
    ];

    const labelX = 50;
    const valueX = 200;
    let y = doc.y;

    doc.fontSize(12);
    doc.moveDown();

    // Draw rows
    tableData.forEach(row => {
        doc.text(`${row.label}:`, labelX, y);
        doc.text(row.value, valueX, y);
        y += 25;
    });

    doc.end();

    stream.on("finish", callback);
}

// ✅ API to download the generated PDF
app.get("/downloadReviewPDF_1", (req, res) => {
    const { paperId } = req.query;

    if (!paperId) {
        return res.status(400).json({ message: "Paper ID is required" });
    }

    const pdfFilePath1 = path.join(__dirname, "uploads", "comment1", `review_${paperId}.pdf`);

    fs.access(pdfFilePath1, fs.constants.F_OK, (err) => {
        if (err) {
            return res.status(404).json({ message: "File not found" });
        }

        res.download(pdfFilePath1, `review_${paperId}.pdf`, (err) => {
            if (err) {
                console.error("Download error:", err);
                res.status(500).json({ message: "Error downloading file" });
            }
        });
    });
});

app.get("/dashboard-counts", (req, res) => {
    const counts = {
        reviewers: 0,
        authors: 0,
        published: 0
    };

    const queries = [
        db.promise().query("SELECT COUNT(*) AS count FROM reviewers"),
        db.promise().query("SELECT COUNT(*) AS count FROM manuscript"),
        db.promise().query("SELECT COUNT(*) AS count FROM manuscript WHERE status = 'published'")
    ];

    Promise.all(queries)
        .then(results => {
            counts.reviewers = results[0][0][0].count;
            counts.authors = results[1][0][0].count;
            counts.published = results[2][0][0].count;
            res.json(counts);
        })
        .catch(err => {
            console.error("Error getting dashboard counts:", err);
            res.status(500).json({ error: "Internal server error" });
        });
});

// 📄 All papers
// app.get("/papers", (req, res) => {
//     const query = "SELECT paperId, title, authors, status, DATE_FORMAT(submissionDate, '%Y-%m-%d') as submissionDate FROM manuscript";
//     db.query(query, (err, results) => {
//         if (err) {
//             console.error("Error fetching papers:", err);
//             return res.status(500).json({ error: "Failed to fetch papers" });
//         }
//         res.json(results);
//     });
// });
app.get("/papers", (req, res) => {
    const query = `
        SELECT 
            paperId, 
            title, 
            authors, 
            status, 
            DATE_FORMAT(submissionDate, '%Y-%m-%d') AS submissionDate 
        FROM manuscript
        ORDER BY CAST(SUBSTRING(paperId, 7) AS UNSIGNED) ASC
    `;

    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching papers:", err);
            return res.status(500).json({ error: "Failed to fetch papers" });
        }
        res.json(results);
    });
});

// 📈 Monthly stats (e.g., submissions per month)
app.get("/monthly-stats", (req, res) => {
    const query = `
        SELECT MONTH(submissionDate) AS month, COUNT(*) AS count
        FROM manuscript
        GROUP BY MONTH(submissionDate)
        ORDER BY month
    `;
    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching monthly stats:", err);
            return res.status(500).json({ error: "Failed to fetch monthly stats" });
        }
        res.json(results);
    });
});

// app.get("/get-publications", (req, res) => {
//     const query = "SELECT paperId, title, authors, status FROM manuscript";
//     db.query(query, (err, results) => {
//       if (err) {
//         console.error("Error fetching publications:", err);
//         return res.status(500).json({ error: "Failed to get publications" });
//       }
//       res.json(results);
//     });
//   });
  
app.get("/get-publications", (req, res) => {
    const query = `
      SELECT paperId, title, authors, status 
      FROM manuscript
     
      ORDER BY CAST(SUBSTRING(paperId, 7) AS UNSIGNED) ASC
    `;
  
    db.query(query, (err, results) => {
      if (err) {
        console.error("Error fetching publications:", err);
        return res.status(500).json({ error: "Failed to get publications" });
      }
      res.json(results);
    });
  });
  

  
  // 3. Publish a paper (update status)
//   app.put("/publish/:id", (req, res) => {
//     const paperId = req.params.id;
//     const query = "UPDATE manuscript SET status = 'published' WHERE paperId = ?";
//     db.query(query, [paperId], (err) => {
//       if (err) {
//         console.error("Error publishing paper:", err);
//         return res.status(500).json({ error: "Failed to publish paper" });
//       }
//       res.json({ message: "Paper published" });
//     });
//   });
app.put("/publish/:id", async (req, res) => {
    const paperId = req.params.id;

    try {
        // Step 1: Update paper status
        const updateQuery = "UPDATE manuscript SET status = 'published' WHERE paperId = ?";
        await db.promise().query(updateQuery, [paperId]);

        // Step 2: Get author's email and name
        const [results] = await db.promise().query("SELECT email, authors, title FROM manuscript WHERE paperId = ?", [paperId]);

        if (results.length === 0) {
            return res.status(404).json({ error: "Paper not found" });
        }

        const { email, authors, title } = results[0];

        // Step 3: Setup Nodemailer with Gmail App Password
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: "thilakraja10@gmail.com",
                pass: "tdai putr abny luxc" // Replace with Gmail App Password
            }
        });

        // Step 4: Compose and send the email
        const mailOptions = {
            from: 'your-email@gmail.com',
            to: email,
            subject: '📢 Your Paper Has Been Published!',
            text: `Dear ${authors},\n\nYour paper titled "${title}" has been successfully published.\n\nThank you for your contribution!\n\nBest regards,\nPublication Team`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.error("❌ Error sending email:", error);
                return res.status(500).json({ message: "Paper published, but email failed", error: error.message });
            }

            console.log("📧 Email sent:", info.response);
            res.json({ message: "Paper published and email sent to the author." });
        });

    } catch (err) {
        console.error("🔥 Error publishing paper:", err);
        res.status(500).json({ error: "Failed to publish paper" });
    }
});

  app.get('/count-published', (req, res) => {
    const query = "SELECT COUNT(*) AS publishedCount FROM manuscript WHERE status = 'Published'";
    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching published count:", err);
            return res.status(500).json({ error: "Failed to fetch count" });
        }
        res.json(results[0]);
    });
});

app.get("/dashboard-counts_1", (req, res) => {
    const counts = {
        reviewers: 0,
        authors: 0,
        published: 0
    };

    const queries = [
        db.promise().query("SELECT COUNT(*) AS count FROM con_reviewerinfo"),
        db.promise().query("SELECT COUNT(*) AS count FROM con_manuscripts"),
        db.promise().query("SELECT COUNT(*) AS count FROM con_manuscripts WHERE status = 'published'")
    ];

    Promise.all(queries)
        .then(results => {
            counts.reviewers = results[0][0][0].count;
            counts.authors = results[1][0][0].count;
            counts.published = results[2][0][0].count;
            res.json(counts);
        })
        .catch(err => {
            console.error("Error getting dashboard counts:", err);
            res.status(500).json({ error: "Internal server error" });
        });
});

// 📄 All papers
app.get("/papers_1", (req, res) => {
    const query = "SELECT paperId, title, authors, status, DATE_FORMAT(submissionDate, '%Y-%m-%d') as submissionDate FROM con_manuscripts ORDER BY CAST(SUBSTRING(paperId, 7) AS UNSIGNED) ASC";
    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching papers:", err);
            return res.status(500).json({ error: "Failed to fetch papers" });
        }
        res.json(results);
    });
});

// 📈 Monthly stats (e.g., submissions per month)
app.get("/monthly-stats_1", (req, res) => {
    const query = `
        SELECT MONTH(submissionDate) AS month, COUNT(*) AS count
        FROM con_manuscripts
        GROUP BY MONTH(submissionDate)
        ORDER BY month
    `;
    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching monthly stats:", err);
            return res.status(500).json({ error: "Failed to fetch monthly stats" });
        }
        res.json(results);
    });
});

app.get("/get-publications_1", (req, res) => {
    const query = "SELECT paperId, title, authors, status FROM con_manuscripts ORDER BY CAST(SUBSTRING(paperId, 7) AS UNSIGNED) ASC";
    db.query(query, (err, results) => {
      if (err) {
        console.error("Error fetching publications:", err);
        return res.status(500).json({ error: "Failed to get publications" });
      }
      res.json(results);
    });
  });
  
  

  
  // 3. Publish a paper (update status)
//   app.put("/publish_1/:id", (req, res) => {
//     const paperId = req.params.id;
//     const query = "UPDATE con_manuscripts SET status = 'published' WHERE paperId = ?";
//     db.query(query, [paperId], (err) => {
//       if (err) {
//         console.error("Error publishing paper:", err);
//         return res.status(500).json({ error: "Failed to publish paper" });
//       }
//       res.json({ message: "Paper published" });
//     });
//   });
app.put("/publish_1/:id", async (req, res) => {
    const paperId = req.params.id;
  
    try {
      // Step 1: Update status
      const updateQuery = "UPDATE con_manuscripts SET status = 'published' WHERE paperId = ?";
      await db.promise().query(updateQuery, [paperId]);
  
      // Step 2: Get author's email, name, and title
      const [results] = await db.promise().query(
        "SELECT email, authors, title FROM con_manuscripts WHERE paperId = ?",
        [paperId]
      );
  
      if (results.length === 0) {
        return res.status(404).json({ error: "Paper not found" });
      }
  
      const { email, authors, title } = results[0];
  
      // Step 3: Configure Nodemailer (using App Password)
      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: "thilakraja10@gmail.com",         // ✅ Replace with your Gmail
          pass: "tdai putr abny luxc"               // ✅ Replace with your Gmail App Password
        }
      });
  
      // Step 4: Setup email content
      const mailOptions = {
        from: "your-email@gmail.com",
        to: email,
        subject: "🎉 Your Conference Paper Has Been Published!",
        text: `Dear ${authors},\n\nWe are pleased to inform you that your paper titled:\n"${title}"\nhas been successfully published in the conference proceedings.\n\nThank you for your valuable contribution.\n\nBest regards,\nConference Management Team`
      };
  
      // Step 5: Send the email
      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error("❌ Error sending email:", error);
          return res.status(500).json({
            message: "Paper published, but email failed to send",
            error: error.message
          });
        }
  
        console.log("📧 Email sent:", info.response);
        res.json({ message: "Paper published and email sent to the author." });
      });
  
    } catch (err) {
      console.error("🔥 Error publishing paper:", err);
      res.status(500).json({ error: "Failed to publish paper" });
    }
  });

  app.get('/count-published_1', (req, res) => {
    const query = "SELECT COUNT(*) AS publishedCount FROM con_manuscripts WHERE status = 'Published'";
    db.query(query, (err, results) => {
        if (err) {
            console.error("Error fetching published count:", err);
            return res.status(500).json({ error: "Failed to fetch count" });
        }
        res.json(results[0]);
    });
});
app.get('/api/status-counts', (req, res) => {
    const query = `SELECT status, COUNT(*) as count FROM con_manuscripts GROUP BY status`;
    db.query(query, (err, results) => {
      if (err) return res.status(500).json({ error: err });
  
      const counts = {};
      results.forEach(row => {
        counts[row.status] = row.count;
      });
  
      res.json(counts);
    });
  });
  